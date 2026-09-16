rule TTP_XOR_QUAD_CurrentVersionRun_44d5 {
  strings:
    $key_44d5 = { 17 ba [2] 33 b4 [2] 18 98 [2] 36 ba [2] 22 a1 [2] 2d bb [2] 33 a6 [2] 31 a7 [2] 2a a1 [2] 36 a6 [2] 2a 89 }

  condition:
    any of them
}