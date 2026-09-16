rule TTP_XOR_QUAD_CurrentVersionRun_66d5 {
  strings:
    $key_66d5 = { 35 ba [2] 11 b4 [2] 3a 98 [2] 14 ba [2] 00 a1 [2] 0f bb [2] 11 a6 [2] 13 a7 [2] 08 a1 [2] 14 a6 [2] 08 89 }

  condition:
    any of them
}