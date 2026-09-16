rule TTP_XOR_QUAD_CurrentVersionRun_81f1 {
  strings:
    $key_81f1 = { d2 9e [2] f6 90 [2] dd bc [2] f3 9e [2] e7 85 [2] e8 9f [2] f6 82 [2] f4 83 [2] ef 85 [2] f3 82 [2] ef ad }

  condition:
    any of them
}