rule TTP_XOR_QUAD_CurrentVersionRun_864a {
  strings:
    $key_864a = { d5 25 [2] f1 2b [2] da 07 [2] f4 25 [2] e0 3e [2] ef 24 [2] f1 39 [2] f3 38 [2] e8 3e [2] f4 39 [2] e8 16 }

  condition:
    any of them
}