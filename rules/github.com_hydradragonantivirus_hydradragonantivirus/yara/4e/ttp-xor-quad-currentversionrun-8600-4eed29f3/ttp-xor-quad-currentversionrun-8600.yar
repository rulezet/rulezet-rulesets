rule TTP_XOR_QUAD_CurrentVersionRun_8600 {
  strings:
    $key_8600 = { d5 6f [2] f1 61 [2] da 4d [2] f4 6f [2] e0 74 [2] ef 6e [2] f1 73 [2] f3 72 [2] e8 74 [2] f4 73 [2] e8 5c }

  condition:
    any of them
}