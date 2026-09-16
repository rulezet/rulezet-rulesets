rule TTP_XOR_QUAD_CurrentVersionRun_864c {
  strings:
    $key_864c = { d5 23 [2] f1 2d [2] da 01 [2] f4 23 [2] e0 38 [2] ef 22 [2] f1 3f [2] f3 3e [2] e8 38 [2] f4 3f [2] e8 10 }

  condition:
    any of them
}