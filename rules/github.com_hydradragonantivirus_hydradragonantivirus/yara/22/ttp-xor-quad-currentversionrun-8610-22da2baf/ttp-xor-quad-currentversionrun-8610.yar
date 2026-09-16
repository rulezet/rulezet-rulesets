rule TTP_XOR_QUAD_CurrentVersionRun_8610 {
  strings:
    $key_8610 = { d5 7f [2] f1 71 [2] da 5d [2] f4 7f [2] e0 64 [2] ef 7e [2] f1 63 [2] f3 62 [2] e8 64 [2] f4 63 [2] e8 4c }

  condition:
    any of them
}