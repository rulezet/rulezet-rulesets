rule TTP_XOR_QUAD_CurrentVersionRun_81d7 {
  strings:
    $key_81d7 = { d2 b8 [2] f6 b6 [2] dd 9a [2] f3 b8 [2] e7 a3 [2] e8 b9 [2] f6 a4 [2] f4 a5 [2] ef a3 [2] f3 a4 [2] ef 8b }

  condition:
    any of them
}