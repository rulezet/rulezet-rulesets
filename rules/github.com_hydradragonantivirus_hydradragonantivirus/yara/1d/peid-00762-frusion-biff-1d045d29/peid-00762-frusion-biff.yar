rule PEiD_00762_Frusion____biff_ {
  meta:
    description = "[Frusion -> biff]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }

  condition:
    $a
}