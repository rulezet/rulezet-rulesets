rule TTP_XOR_QUAD_CurrentVersionRun_8636 {
  strings:
    $key_8636 = { d5 59 [2] f1 57 [2] da 7b [2] f4 59 [2] e0 42 [2] ef 58 [2] f1 45 [2] f3 44 [2] e8 42 [2] f4 45 [2] e8 6a }

  condition:
    any of them
}