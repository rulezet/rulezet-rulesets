rule TTP_XOR_QUAD_CurrentVersionRun_866f {
  strings:
    $key_866f = { d5 00 [2] f1 0e [2] da 22 [2] f4 00 [2] e0 1b [2] ef 01 [2] f1 1c [2] f3 1d [2] e8 1b [2] f4 1c [2] e8 33 }

  condition:
    any of them
}