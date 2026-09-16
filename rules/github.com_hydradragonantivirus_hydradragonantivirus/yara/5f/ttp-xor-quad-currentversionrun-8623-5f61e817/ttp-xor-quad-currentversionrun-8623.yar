rule TTP_XOR_QUAD_CurrentVersionRun_8623 {
  strings:
    $key_8623 = { d5 4c [2] f1 42 [2] da 6e [2] f4 4c [2] e0 57 [2] ef 4d [2] f1 50 [2] f3 51 [2] e8 57 [2] f4 50 [2] e8 7f }

  condition:
    any of them
}