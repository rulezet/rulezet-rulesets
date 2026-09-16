rule TTP_XOR_QUAD_CurrentVersionRun_86c7 {
  strings:
    $key_86c7 = { d5 a8 [2] f1 a6 [2] da 8a [2] f4 a8 [2] e0 b3 [2] ef a9 [2] f1 b4 [2] f3 b5 [2] e8 b3 [2] f4 b4 [2] e8 9b }

  condition:
    any of them
}