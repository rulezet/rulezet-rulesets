rule TTP_XOR_QUAD_CurrentVersionRun_6ed4 {
  strings:
    $key_6ed4 = { 3d bb [2] 19 b5 [2] 32 99 [2] 1c bb [2] 08 a0 [2] 07 ba [2] 19 a7 [2] 1b a6 [2] 00 a0 [2] 1c a7 [2] 00 88 }

  condition:
    any of them
}