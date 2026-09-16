rule TTP_XOR_QUAD_CurrentVersionRun_81f5 {
  strings:
    $key_81f5 = { d2 9a [2] f6 94 [2] dd b8 [2] f3 9a [2] e7 81 [2] e8 9b [2] f6 86 [2] f4 87 [2] ef 81 [2] f3 86 [2] ef a9 }

  condition:
    any of them
}