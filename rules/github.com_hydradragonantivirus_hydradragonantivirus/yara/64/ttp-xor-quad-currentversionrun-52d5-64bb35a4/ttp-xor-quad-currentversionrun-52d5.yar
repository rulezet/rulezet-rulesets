rule TTP_XOR_QUAD_CurrentVersionRun_52d5 {
  strings:
    $key_52d5 = { 01 ba [2] 25 b4 [2] 0e 98 [2] 20 ba [2] 34 a1 [2] 3b bb [2] 25 a6 [2] 27 a7 [2] 3c a1 [2] 20 a6 [2] 3c 89 }

  condition:
    any of them
}