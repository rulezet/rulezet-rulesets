rule PEiD_03517_y0da_s_Crypter_v1_1_ {
  meta:
    description = "[y0da's Crypter v1.1]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }

  condition:
    $a
}