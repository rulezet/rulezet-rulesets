rule TTP_XOR_QUAD_CurrentVersionRun_36d5 {
  strings:
    $key_36d5 = { 65 ba [2] 41 b4 [2] 6a 98 [2] 44 ba [2] 50 a1 [2] 5f bb [2] 41 a6 [2] 43 a7 [2] 58 a1 [2] 44 a6 [2] 58 89 }

  condition:
    any of them
}