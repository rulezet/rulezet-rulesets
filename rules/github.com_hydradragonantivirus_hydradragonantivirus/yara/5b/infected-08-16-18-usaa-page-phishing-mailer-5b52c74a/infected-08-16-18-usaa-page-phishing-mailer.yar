rule infected_08_16_18_usaa_page_phishing_mailer {
  meta:
    description = "phishing - file mailer.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-16"
    hash1       = "4fb064375415e844bed994aebe1caf09b9a646f20d4daceefb4f4f4262af007c"

  strings:
        $s2  = "$headers = \"From: usaa result<customer-support@mrs>\";" fullword ascii
    $s3  = "$message .= \"Email Address             : \".$_POST['formtext3'].\"\\n\";" fullword ascii
    $s4  = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s5  = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s6  = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s7  = "$message .= \"Confirm PIN Number           : \".$_POST['formtext12'].\"\\n\";" fullword ascii
    $s8  = "$message .= \"Date of Birth             : \".$_POST['formtext8'].\"\\n\";" fullword ascii
    $s9  = "$message .= \"USAA Member Number            : \".$_POST['formtext2'].\"\\n\";" fullword ascii
    $s10 = "mail($send,$subject,$message,$headers);" fullword ascii
    $s11 = "mail($to,$subject,$message,$headers);" fullword ascii
    $s12 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii
    $s13 = "$subject = \"Result from -$ip\";" fullword ascii
    $s14 = "$message .= \"Phone Pin           : \".$_POST['formtext13'].\"\\n\";" fullword ascii
    $s15 = "$message .= \"Full Name             : \".$_POST['formtext1'].\"\\n\";" fullword ascii
    $s16 = "$message .= \"SSN 1             : \".$_POST['formtext5'].\"\\n\";" fullword ascii
    $s17 = "$message .= \"Expiry Date          : \".$_POST['formtext10'].\"\\n\";" fullword ascii
    $s18 = "$message .= \"SSN 3             : \".$_POST['formtext7'].\"\\n\";" fullword ascii
    $s19 = "$message .= \"SSN 2             : \".$_POST['formtext6'].\"\\n\";" fullword ascii
    $s20 = "$message .= \"--------------Skype Info-----------------------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (8 of them)
    ) or (all of them)
}