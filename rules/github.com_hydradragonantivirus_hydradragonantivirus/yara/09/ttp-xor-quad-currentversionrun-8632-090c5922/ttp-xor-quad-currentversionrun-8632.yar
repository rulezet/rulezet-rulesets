rule TTP_XOR_QUAD_CurrentVersionRun_8632 {
  strings:
    $key_8632 = { d5 5d [2] f1 53 [2] da 7f [2] f4 5d [2] e0 46 [2] ef 5c [2] f1 41 [2] f3 40 [2] e8 46 [2] f4 41 [2] e8 6e }

  condition:
    any of them
}