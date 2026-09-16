rule TTP_XOR_QUAD_CurrentVersionRun_54d5 {
  strings:
    $key_54d5 = { 07 ba [2] 23 b4 [2] 08 98 [2] 26 ba [2] 32 a1 [2] 3d bb [2] 23 a6 [2] 21 a7 [2] 3a a1 [2] 26 a6 [2] 3a 89 }

  condition:
    any of them
}