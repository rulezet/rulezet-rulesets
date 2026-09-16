rule TTP_XOR_QUAD_CurrentVersionRun_6625 {
  strings:
    $key_6625 = { 35 4a [2] 11 44 [2] 3a 68 [2] 14 4a [2] 00 51 [2] 0f 4b [2] 11 56 [2] 13 57 [2] 08 51 [2] 14 56 [2] 08 79 }

  condition:
    any of them
}