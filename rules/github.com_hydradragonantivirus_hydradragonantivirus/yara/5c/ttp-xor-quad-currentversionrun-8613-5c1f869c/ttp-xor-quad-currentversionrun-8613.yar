rule TTP_XOR_QUAD_CurrentVersionRun_8613 {
  strings:
    $key_8613 = { d5 7c [2] f1 72 [2] da 5e [2] f4 7c [2] e0 67 [2] ef 7d [2] f1 60 [2] f3 61 [2] e8 67 [2] f4 60 [2] e8 4f }

  condition:
    any of them
}