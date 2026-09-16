rule TTP_XOR_QUAD_CurrentVersionRun_7fd5 {
  strings:
    $key_7fd5 = { 2c ba [2] 08 b4 [2] 23 98 [2] 0d ba [2] 19 a1 [2] 16 bb [2] 08 a6 [2] 0a a7 [2] 11 a1 [2] 0d a6 [2] 11 89 }

  condition:
    any of them
}