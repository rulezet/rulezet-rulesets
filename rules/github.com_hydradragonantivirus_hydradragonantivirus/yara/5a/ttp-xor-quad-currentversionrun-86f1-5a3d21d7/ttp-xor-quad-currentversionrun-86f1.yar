rule TTP_XOR_QUAD_CurrentVersionRun_86f1 {
  strings:
    $key_86f1 = { d5 9e [2] f1 90 [2] da bc [2] f4 9e [2] e0 85 [2] ef 9f [2] f1 82 [2] f3 83 [2] e8 85 [2] f4 82 [2] e8 ad }

  condition:
    any of them
}