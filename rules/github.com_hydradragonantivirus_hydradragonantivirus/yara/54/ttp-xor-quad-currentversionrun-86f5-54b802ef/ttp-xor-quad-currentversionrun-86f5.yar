rule TTP_XOR_QUAD_CurrentVersionRun_86f5 {
  strings:
    $key_86f5 = { d5 9a [2] f1 94 [2] da b8 [2] f4 9a [2] e0 81 [2] ef 9b [2] f1 86 [2] f3 87 [2] e8 81 [2] f4 86 [2] e8 a9 }

  condition:
    any of them
}