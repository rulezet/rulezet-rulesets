rule tElockv051_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 5E 8B FE 68 79 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }

  condition:
    $a0
}