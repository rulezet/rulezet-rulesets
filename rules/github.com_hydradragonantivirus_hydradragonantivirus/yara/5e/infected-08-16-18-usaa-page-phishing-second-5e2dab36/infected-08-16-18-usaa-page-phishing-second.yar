rule infected_08_16_18_usaa_page_phishing_second {
  meta:
    description = "phishing - file second.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-16"
    hash1       = "fcbd6b43f0447982d3195483d69a03c9c8095cd0e1b7ecd33784cd21e81a8b33"

  strings:
        $s2  = "$headers = \"From: Usaa result<customer-support@mrs>\";" fullword ascii
    $s3  = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s4  = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s5  = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s6  = "mail($send,$subject,$message,$headers);" fullword ascii
    $s7  = "mail($to,$subject,$message,$headers);" fullword ascii
    $s8  = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
    $s9  = "$subject = \"Result from -$ip\";" fullword ascii
    $s10 = "$message .= \"Pin            : \".$_POST['formtext103'].\"\\n\";" fullword ascii
    $s11 = "$message .= \"--------------Usaa Pin Info-----------------------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}