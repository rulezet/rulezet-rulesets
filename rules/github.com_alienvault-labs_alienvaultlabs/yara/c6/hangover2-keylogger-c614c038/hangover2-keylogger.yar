rule Hangover2_Keylogger {

  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > " wide ascii

    $c = "Global\\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them
}