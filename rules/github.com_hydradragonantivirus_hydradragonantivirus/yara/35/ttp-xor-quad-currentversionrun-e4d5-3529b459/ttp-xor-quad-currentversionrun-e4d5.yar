rule TTP_XOR_QUAD_CurrentVersionRun_e4d5 {
  strings:
    $key_e4d5 = { b7 ba [2] 93 b4 [2] b8 98 [2] 96 ba [2] 82 a1 [2] 8d bb [2] 93 a6 [2] 91 a7 [2] 8a a1 [2] 96 a6 [2] 8a 89 }

  condition:
    any of them
}