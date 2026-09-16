rule TTP_XOR_QUAD_CurrentVersionRun_81e0 {
  strings:
    $key_81e0 = { d2 8f [2] f6 81 [2] dd ad [2] f3 8f [2] e7 94 [2] e8 8e [2] f6 93 [2] f4 92 [2] ef 94 [2] f3 93 [2] ef bc }

  condition:
    any of them
}