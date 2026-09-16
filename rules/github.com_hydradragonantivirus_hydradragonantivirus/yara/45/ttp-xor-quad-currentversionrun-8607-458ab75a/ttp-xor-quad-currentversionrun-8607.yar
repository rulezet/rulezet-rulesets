rule TTP_XOR_QUAD_CurrentVersionRun_8607 {
  strings:
    $key_8607 = { d5 68 [2] f1 66 [2] da 4a [2] f4 68 [2] e0 73 [2] ef 69 [2] f1 74 [2] f3 75 [2] e8 73 [2] f4 74 [2] e8 5b }

  condition:
    any of them
}