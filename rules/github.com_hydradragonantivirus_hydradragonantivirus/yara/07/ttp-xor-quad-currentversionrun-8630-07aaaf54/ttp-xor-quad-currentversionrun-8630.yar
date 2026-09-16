rule TTP_XOR_QUAD_CurrentVersionRun_8630 {
  strings:
    $key_8630 = { d5 5f [2] f1 51 [2] da 7d [2] f4 5f [2] e0 44 [2] ef 5e [2] f1 43 [2] f3 42 [2] e8 44 [2] f4 43 [2] e8 6c }

  condition:
    any of them
}