rule TTP_XOR_QUAD_CurrentVersionRun_e4d4 {
  strings:
    $key_e4d4 = { b7 bb [2] 93 b5 [2] b8 99 [2] 96 bb [2] 82 a0 [2] 8d ba [2] 93 a7 [2] 91 a6 [2] 8a a0 [2] 96 a7 [2] 8a 88 }

  condition:
    any of them
}