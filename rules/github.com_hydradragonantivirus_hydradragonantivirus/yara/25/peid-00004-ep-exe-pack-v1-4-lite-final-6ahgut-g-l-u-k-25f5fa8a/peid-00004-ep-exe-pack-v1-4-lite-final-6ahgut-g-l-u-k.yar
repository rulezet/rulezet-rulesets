rule PEiD_00004__EP_ExE_Pack__V1_4_lite_final____6aHguT___g_l_u_k_ {
  meta:
    description = "[!EP(ExE Pack) V1.4 lite final -> 6aHguT & g-l-u-k]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 61 B8 ?? ?? ?? ?? FF E0 55 8B EC 60 55 8B 75 08 8B 7D 0C E8 02 00 00 00 EB 04 8B 1C 24 C3 81 C3 00 02 00 00 53 57 8B 07 89 03 83 C7 04 83 C3 04 4E 75 F3 5F 5E FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 46 12 D2 73 EF 02 D2 75 05 8A 16 46 12 }

  condition:
    $a
}