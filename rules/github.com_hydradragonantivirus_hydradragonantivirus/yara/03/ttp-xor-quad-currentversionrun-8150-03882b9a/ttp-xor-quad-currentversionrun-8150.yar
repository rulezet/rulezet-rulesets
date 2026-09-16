rule TTP_XOR_QUAD_CurrentVersionRun_8150 {
  strings:
    $key_8150 = { d2 3f [2] f6 31 [2] dd 1d [2] f3 3f [2] e7 24 [2] e8 3e [2] f6 23 [2] f4 22 [2] ef 24 [2] f3 23 [2] ef 0c }

  condition:
    any of them
}