rule TTP_XOR_QUAD_CurrentVersionRun_6677 {
  strings:
    $key_6677 = { 35 18 [2] 11 16 [2] 3a 3a [2] 14 18 [2] 00 03 [2] 0f 19 [2] 11 04 [2] 13 05 [2] 08 03 [2] 14 04 [2] 08 2b }

  condition:
    any of them
}