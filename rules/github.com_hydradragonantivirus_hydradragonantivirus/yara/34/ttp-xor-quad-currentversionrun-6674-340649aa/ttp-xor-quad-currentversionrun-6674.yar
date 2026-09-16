rule TTP_XOR_QUAD_CurrentVersionRun_6674 {
  strings:
    $key_6674 = { 35 1b [2] 11 15 [2] 3a 39 [2] 14 1b [2] 00 00 [2] 0f 1a [2] 11 07 [2] 13 06 [2] 08 00 [2] 14 07 [2] 08 28 }

  condition:
    any of them
}