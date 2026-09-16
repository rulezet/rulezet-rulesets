rule TTP_XOR_QUAD_CurrentVersionRun_8629 {
  strings:
    $key_8629 = { d5 46 [2] f1 48 [2] da 64 [2] f4 46 [2] e0 5d [2] ef 47 [2] f1 5a [2] f3 5b [2] e8 5d [2] f4 5a [2] e8 75 }

  condition:
    any of them
}