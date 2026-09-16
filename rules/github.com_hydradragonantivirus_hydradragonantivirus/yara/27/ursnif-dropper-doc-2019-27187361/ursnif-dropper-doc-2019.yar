rule ursnif_dropper_doc_2019 {
  meta:
    author    = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $sleep = "WScript.Sleep(56000)" wide ascii nocase
    $js    = ".js" wide ascii
    $ret   = "return \"Ru\" + \"\\x6e\""      $pse   = "powershell -Enc "  
  condition:
    uint16(0) == 0xcfd0 and all of them
}