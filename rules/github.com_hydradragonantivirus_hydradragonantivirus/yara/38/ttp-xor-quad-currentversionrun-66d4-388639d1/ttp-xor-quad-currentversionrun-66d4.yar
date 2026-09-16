rule TTP_XOR_QUAD_CurrentVersionRun_66d4 {
  strings:
    $key_66d4 = { 35 bb [2] 11 b5 [2] 3a 99 [2] 14 bb [2] 00 a0 [2] 0f ba [2] 11 a7 [2] 13 a6 [2] 08 a0 [2] 14 a7 [2] 08 88 }

  condition:
    any of them
}