rule TTP_XOR_QUAD_CurrentVersionRun_37d4 {
  strings:
    $key_37d4 = { 64 bb [2] 40 b5 [2] 6b 99 [2] 45 bb [2] 51 a0 [2] 5e ba [2] 40 a7 [2] 42 a6 [2] 59 a0 [2] 45 a7 [2] 59 88 }

  condition:
    any of them
}