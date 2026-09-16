rule TTP_XOR_QUAD_CurrentVersionRun_8ed5 {
  strings:
    $key_8ed5 = { dd ba [2] f9 b4 [2] d2 98 [2] fc ba [2] e8 a1 [2] e7 bb [2] f9 a6 [2] fb a7 [2] e0 a1 [2] fc a6 [2] e0 89 }

  condition:
    any of them
}