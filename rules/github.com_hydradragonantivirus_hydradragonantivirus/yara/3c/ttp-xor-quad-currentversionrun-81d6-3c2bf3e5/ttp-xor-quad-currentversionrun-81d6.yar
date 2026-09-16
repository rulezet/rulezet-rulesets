rule TTP_XOR_QUAD_CurrentVersionRun_81d6 {
  strings:
    $key_81d6 = { d2 b9 [2] f6 b7 [2] dd 9b [2] f3 b9 [2] e7 a2 [2] e8 b8 [2] f6 a5 [2] f4 a4 [2] ef a2 [2] f3 a5 [2] ef 8a }

  condition:
    any of them
}