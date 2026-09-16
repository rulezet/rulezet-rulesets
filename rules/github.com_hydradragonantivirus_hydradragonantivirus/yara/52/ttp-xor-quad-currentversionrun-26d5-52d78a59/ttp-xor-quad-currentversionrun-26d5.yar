rule TTP_XOR_QUAD_CurrentVersionRun_26d5 {
  strings:
    $key_26d5 = { 75 ba [2] 51 b4 [2] 7a 98 [2] 54 ba [2] 40 a1 [2] 4f bb [2] 51 a6 [2] 53 a7 [2] 48 a1 [2] 54 a6 [2] 48 89 }

  condition:
    any of them
}