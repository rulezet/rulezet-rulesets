rule TTP_XOR_QUAD_CurrentVersionRun_8661 {
  strings:
    $key_8661 = { d5 0e [2] f1 00 [2] da 2c [2] f4 0e [2] e0 15 [2] ef 0f [2] f1 12 [2] f3 13 [2] e8 15 [2] f4 12 [2] e8 3d }

  condition:
    any of them
}