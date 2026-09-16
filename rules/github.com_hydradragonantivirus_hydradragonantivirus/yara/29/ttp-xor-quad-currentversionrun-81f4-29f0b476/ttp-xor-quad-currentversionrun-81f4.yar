rule TTP_XOR_QUAD_CurrentVersionRun_81f4 {
  strings:
    $key_81f4 = { d2 9b [2] f6 95 [2] dd b9 [2] f3 9b [2] e7 80 [2] e8 9a [2] f6 87 [2] f4 86 [2] ef 80 [2] f3 87 [2] ef a8 }

  condition:
    any of them
}