rule TTP_XOR_QUAD_CurrentVersionRun_8617 {
  strings:
    $key_8617 = { d5 78 [2] f1 76 [2] da 5a [2] f4 78 [2] e0 63 [2] ef 79 [2] f1 64 [2] f3 65 [2] e8 63 [2] f4 64 [2] e8 4b }

  condition:
    any of them
}