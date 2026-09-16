rule TTP_XOR_QUAD_CurrentVersionRun_8656 {
  strings:
    $key_8656 = { d5 39 [2] f1 37 [2] da 1b [2] f4 39 [2] e0 22 [2] ef 38 [2] f1 25 [2] f3 24 [2] e8 22 [2] f4 25 [2] e8 0a }

  condition:
    any of them
}