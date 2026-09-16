rule warning_powershell_strings {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = false
    rank       = 5
    revision   = "1"
    date       = "Feb 15 2018"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2017. All rights reserved."
    tlp        = "red"
    sigtype    = "cryptam_exploit"
    desc       = "Powershell"

  strings:
    $s1 = "powershell.exe"
    $s2 = "-nop -w hidden -encodedcommand"
    $s3 = "Package"
    $s4 = "Ole10Native" wide

  condition:
    3 of them
}