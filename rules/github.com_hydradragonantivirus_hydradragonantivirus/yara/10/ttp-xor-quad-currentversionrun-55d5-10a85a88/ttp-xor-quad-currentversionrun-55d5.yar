rule TTP_XOR_QUAD_CurrentVersionRun_55d5 {
  strings:
    $key_55d5 = { 06 ba [2] 22 b4 [2] 09 98 [2] 27 ba [2] 33 a1 [2] 3c bb [2] 22 a6 [2] 20 a7 [2] 3b a1 [2] 27 a6 [2] 3b 89 }

  condition:
    any of them
}