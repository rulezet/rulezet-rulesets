rule PEiD_03354_vprotector_1_3____vcasm_ {
  meta:
    description = "[vprotector 1.3 -> vcasm]"
    ep_only     = "true"

  strings:
    $a = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 }

  condition:
    $a
}