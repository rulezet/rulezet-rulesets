rule TTP_XOR_QUAD_CurrentVersionRun_75d5 {
  strings:
    $key_75d5 = { 26 ba [2] 02 b4 [2] 29 98 [2] 07 ba [2] 13 a1 [2] 1c bb [2] 02 a6 [2] 00 a7 [2] 1b a1 [2] 07 a6 [2] 1b 89 }

  condition:
    any of them
}