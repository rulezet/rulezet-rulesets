rule TTP_XOR_QUAD_CurrentVersionRun_861d {
  strings:
    $key_861d = { d5 72 [2] f1 7c [2] da 50 [2] f4 72 [2] e0 69 [2] ef 73 [2] f1 6e [2] f3 6f [2] e8 69 [2] f4 6e [2] e8 41 }

  condition:
    any of them
}