rule TTP_XOR_QUAD_CurrentVersionRun_76d4 {
  strings:
    $key_76d4 = { 25 bb [2] 01 b5 [2] 2a 99 [2] 04 bb [2] 10 a0 [2] 1f ba [2] 01 a7 [2] 03 a6 [2] 18 a0 [2] 04 a7 [2] 18 88 }

  condition:
    any of them
}