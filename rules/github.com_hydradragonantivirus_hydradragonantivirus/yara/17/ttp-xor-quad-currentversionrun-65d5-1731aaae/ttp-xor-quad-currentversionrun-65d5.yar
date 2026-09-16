rule TTP_XOR_QUAD_CurrentVersionRun_65d5 {
  strings:
    $key_65d5 = { 36 ba [2] 12 b4 [2] 39 98 [2] 17 ba [2] 03 a1 [2] 0c bb [2] 12 a6 [2] 10 a7 [2] 0b a1 [2] 17 a6 [2] 0b 89 }

  condition:
    any of them
}