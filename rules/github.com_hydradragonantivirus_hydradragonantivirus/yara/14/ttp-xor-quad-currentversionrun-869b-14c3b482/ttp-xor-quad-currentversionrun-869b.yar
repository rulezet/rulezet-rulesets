rule TTP_XOR_QUAD_CurrentVersionRun_869b {
  strings:
    $key_869b = { d5 f4 [2] f1 fa [2] da d6 [2] f4 f4 [2] e0 ef [2] ef f5 [2] f1 e8 [2] f3 e9 [2] e8 ef [2] f4 e8 [2] e8 c7 }

  condition:
    any of them
}