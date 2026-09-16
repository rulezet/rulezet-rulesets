rule TTP_XOR_QUAD_CurrentVersionRun_862e {
  strings:
    $key_862e = { d5 41 [2] f1 4f [2] da 63 [2] f4 41 [2] e0 5a [2] ef 40 [2] f1 5d [2] f3 5c [2] e8 5a [2] f4 5d [2] e8 72 }

  condition:
    any of them
}