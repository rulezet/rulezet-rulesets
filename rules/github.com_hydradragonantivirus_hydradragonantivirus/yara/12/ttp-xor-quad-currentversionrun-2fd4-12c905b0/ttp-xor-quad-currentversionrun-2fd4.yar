rule TTP_XOR_QUAD_CurrentVersionRun_2fd4 {
  strings:
    $key_2fd4 = { 7c bb [2] 58 b5 [2] 73 99 [2] 5d bb [2] 49 a0 [2] 46 ba [2] 58 a7 [2] 5a a6 [2] 41 a0 [2] 5d a7 [2] 41 88 }

  condition:
    any of them
}