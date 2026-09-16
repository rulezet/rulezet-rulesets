rule TTP_XOR_QUAD_CurrentVersionRun_81d5 {
  strings:
    $key_81d5 = { d2 ba [2] f6 b4 [2] dd 98 [2] f3 ba [2] e7 a1 [2] e8 bb [2] f6 a6 [2] f4 a7 [2] ef a1 [2] f3 a6 [2] ef 89 }

  condition:
    any of them
}