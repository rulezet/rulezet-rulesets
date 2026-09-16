rule TTP_XOR_QUAD_CurrentVersionRun_867c {
  strings:
    $key_867c = { d5 13 [2] f1 1d [2] da 31 [2] f4 13 [2] e0 08 [2] ef 12 [2] f1 0f [2] f3 0e [2] e8 08 [2] f4 0f [2] e8 20 }

  condition:
    any of them
}