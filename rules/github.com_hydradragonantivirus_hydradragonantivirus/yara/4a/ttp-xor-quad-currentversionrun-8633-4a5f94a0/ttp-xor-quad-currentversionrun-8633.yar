rule TTP_XOR_QUAD_CurrentVersionRun_8633 {
  strings:
    $key_8633 = { d5 5c [2] f1 52 [2] da 7e [2] f4 5c [2] e0 47 [2] ef 5d [2] f1 40 [2] f3 41 [2] e8 47 [2] f4 40 [2] e8 6f }

  condition:
    any of them
}