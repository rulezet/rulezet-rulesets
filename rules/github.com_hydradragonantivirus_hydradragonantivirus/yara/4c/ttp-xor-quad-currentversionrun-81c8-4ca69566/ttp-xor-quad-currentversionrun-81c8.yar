rule TTP_XOR_QUAD_CurrentVersionRun_81c8 {
  strings:
    $key_81c8 = { d2 a7 [2] f6 a9 [2] dd 85 [2] f3 a7 [2] e7 bc [2] e8 a6 [2] f6 bb [2] f4 ba [2] ef bc [2] f3 bb [2] ef 94 }

  condition:
    any of them
}