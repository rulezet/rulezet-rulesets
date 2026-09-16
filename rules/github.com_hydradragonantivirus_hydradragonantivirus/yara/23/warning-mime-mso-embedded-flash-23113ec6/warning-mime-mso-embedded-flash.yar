rule warning_mime_mso_embedded_flash {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 1
    revision   = "1"
    date       = "July 29 2015"
    author     = "@tylabs"
    copyright  = "QuickSand.io (c) Copyright 2015. All rights reserved."
    tlp        = "white"
    release    = "lite"
    sigtype    = "cryptam_exploit"
    desc       = "office embedded Flash in MSO file"

  strings:
    $s1 = "D27CDB6E-AE6D-11CF-96B8-444553540000" nocase

  condition:
    1 of them
}