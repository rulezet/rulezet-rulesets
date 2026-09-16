rule TTP_XOR_QUAD_CurrentVersionRun_862c {
  strings:
    $key_862c = { d5 43 [2] f1 4d [2] da 61 [2] f4 43 [2] e0 58 [2] ef 42 [2] f1 5f [2] f3 5e [2] e8 58 [2] f4 5f [2] e8 70 }

  condition:
    any of them
}