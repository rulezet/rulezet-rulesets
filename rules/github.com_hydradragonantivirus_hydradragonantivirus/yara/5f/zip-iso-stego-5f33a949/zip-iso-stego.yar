rule zip_iso_stego {
  meta:
    author      = "jeFF0Falltrades"
    description = "This rule identifies a specific phishing technique of sending ISO file attachments containing ZIP (and JAR, APK, DOCX, etc.) archives which in turn contain malicious executables."

  strings:
    $iso_header = "CD001"      $exe_zip    = { 2e 65 78 65 50 4b 05 06 00 00 00 00 01 00 01 }  
  condition:
    (($iso_header at 0x8001) or ($iso_header at 0x8801) or ($iso_header at 0x9001)) and $exe_zip
}