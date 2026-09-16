rule TTP_XOR_QUAD_CurrentVersionRun_865d {
  strings:
    $key_865d = { d5 32 [2] f1 3c [2] da 10 [2] f4 32 [2] e0 29 [2] ef 33 [2] f1 2e [2] f3 2f [2] e8 29 [2] f4 2e [2] e8 01 }

  condition:
    any of them
}