rule TTP_XOR_QUAD_CurrentVersionRun_81c9 {
  strings:
    $key_81c9 = { d2 a6 [2] f6 a8 [2] dd 84 [2] f3 a6 [2] e7 bd [2] e8 a7 [2] f6 ba [2] f4 bb [2] ef bd [2] f3 ba [2] ef 95 }

  condition:
    any of them
}