rule TTP_XOR_QUAD_CurrentVersionRun_860b {
  strings:
    $key_860b = { d5 64 [2] f1 6a [2] da 46 [2] f4 64 [2] e0 7f [2] ef 65 [2] f1 78 [2] f3 79 [2] e8 7f [2] f4 78 [2] e8 57 }

  condition:
    any of them
}