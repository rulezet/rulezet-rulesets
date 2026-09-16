rule TTP_XOR_QUAD_CurrentVersionRun_6654 {
  strings:
    $key_6654 = { 35 3b [2] 11 35 [2] 3a 19 [2] 14 3b [2] 00 20 [2] 0f 3a [2] 11 27 [2] 13 26 [2] 08 20 [2] 14 27 [2] 08 08 }

  condition:
    any of them
}