rule TTP_XOR_QUAD_CurrentVersionRun_867e {
  strings:
    $key_867e = { d5 11 [2] f1 1f [2] da 33 [2] f4 11 [2] e0 0a [2] ef 10 [2] f1 0d [2] f3 0c [2] e8 0a [2] f4 0d [2] e8 22 }

  condition:
    any of them
}