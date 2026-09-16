rule TTP_XOR_QUAD_CurrentVersionRun_44d4 {
  strings:
    $key_44d4 = { 17 bb [2] 33 b5 [2] 18 99 [2] 36 bb [2] 22 a0 [2] 2d ba [2] 33 a7 [2] 31 a6 [2] 2a a0 [2] 36 a7 [2] 2a 88 }

  condition:
    any of them
}