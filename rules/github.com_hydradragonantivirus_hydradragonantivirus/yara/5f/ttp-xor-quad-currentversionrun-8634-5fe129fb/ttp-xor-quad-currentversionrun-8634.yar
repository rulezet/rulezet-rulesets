rule TTP_XOR_QUAD_CurrentVersionRun_8634 {
  strings:
    $key_8634 = { d5 5b [2] f1 55 [2] da 79 [2] f4 5b [2] e0 40 [2] ef 5a [2] f1 47 [2] f3 46 [2] e8 40 [2] f4 47 [2] e8 68 }

  condition:
    any of them
}