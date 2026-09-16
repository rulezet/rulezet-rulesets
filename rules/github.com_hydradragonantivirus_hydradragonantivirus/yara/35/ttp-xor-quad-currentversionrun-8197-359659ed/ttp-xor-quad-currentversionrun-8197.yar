rule TTP_XOR_QUAD_CurrentVersionRun_8197 {
  strings:
    $key_8197 = { d2 f8 [2] f6 f6 [2] dd da [2] f3 f8 [2] e7 e3 [2] e8 f9 [2] f6 e4 [2] f4 e5 [2] ef e3 [2] f3 e4 [2] ef cb }

  condition:
    any of them
}