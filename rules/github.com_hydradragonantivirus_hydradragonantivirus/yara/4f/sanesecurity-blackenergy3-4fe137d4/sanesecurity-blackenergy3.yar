rule Sanesecurity_BlackEnergy3 {
  strings:
    $a1 = "MCSF_Config" ascii
    $a2 = "NTUSER.LOG" ascii
    $a3 = "ldplg" ascii
    $a4 = "unlplg" ascii
    $a5 = "getp" ascii
    $a6 = "getpd" ascii
    $a7 = "CSTR" ascii
    $a8 = "FONTCACHE.DAT" ascii

  condition:
    4 of them
}