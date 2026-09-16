rule TTP_XOR_QUAD_CurrentVersionRun_865c {
  strings:
    $key_865c = { d5 33 [2] f1 3d [2] da 11 [2] f4 33 [2] e0 28 [2] ef 32 [2] f1 2f [2] f3 2e [2] e8 28 [2] f4 2f [2] e8 00 }

  condition:
    any of them
}