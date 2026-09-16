rule infected_08_16_18_usaa_page_phishing_action {
  meta:
    description = "phishing - file action.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-16"
    hash1       = "44e246c90089c88c7583c11d5e410176480b9e2f89b882ee45a831602ce3eca8"

  strings:
    $s1  = "$send = \"mandrell009@gmail.com,born.last@yandex.com\";" fullword ascii
    $s2  = "$headers = \"From: USAA result<customer-support@mrs>\";" fullword ascii
    $s3  = "$message .= \"Question 1 : \".$_POST['formselect1'].\"\\n\";" fullword ascii
    $s4  = "$message .= \"Answer  1 : \".$_POST['formtext1'].\"\\n\";" fullword ascii
    $s5  = "$message .= \"Answer 3 : \".$_POST['formtext3'].\"\\n\";" fullword ascii
    $s6  = "$message .= \"Question 2 : \".$_POST['formselect2'].\"\\n\";" fullword ascii
    $s7  = "$message .= \"Answer 2 : \".$_POST['formtext2'].\"\\n\";" fullword ascii
    $s8  = "$message .= \"Question 3  : \".$_POST['formselect3'].\"\\n\";" fullword ascii
    $s9  = "$message .= \"Question 4 : \".$_POST['formselect4'].\"\\n\";" fullword ascii
    $s10 = "$message .= \"Answer 4 : \".$_POST['formtext4'].\"\\n\";" fullword ascii
    $s11 = "$message .= \"Question 5 : \".$_POST['formselect5'].\"\\n\";" fullword ascii
    $s12 = "$message .= \"Question 6 : \".$_POST['formselect6'].\"\\n\";" fullword ascii
    $s13 = "$message .= \"Answer 5 : \".$_POST['formtext5'].\"\\n\";" fullword ascii
    $s14 = "$message .= \"Answer 6 : \".$_POST['formtext6'].\"\\n\";" fullword ascii
    $s15 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s16 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s17 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s18 = "mail($send,$subject,$message,$headers);" fullword ascii
    $s19 = "mail($to,$subject,$message,$headers);" fullword ascii
    $s20 = "$message .= \"---------------Created BY Unknown-------------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 3KB and
      (8 of them)
    ) or (all of them)
}