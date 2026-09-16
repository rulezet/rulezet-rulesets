rule TTP_XOR_QUAD_CurrentVersionRun_14d4 {
  strings:
    $key_14d4 = { 47 bb [2] 63 b5 [2] 48 99 [2] 66 bb [2] 72 a0 [2] 7d ba [2] 63 a7 [2] 61 a6 [2] 7a a0 [2] 66 a7 [2] 7a 88 }

  condition:
    any of them
}