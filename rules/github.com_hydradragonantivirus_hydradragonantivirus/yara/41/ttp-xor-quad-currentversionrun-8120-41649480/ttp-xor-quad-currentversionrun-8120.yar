rule TTP_XOR_QUAD_CurrentVersionRun_8120 {
  strings:
    $key_8120 = { d2 4f [2] f6 41 [2] dd 6d [2] f3 4f [2] e7 54 [2] e8 4e [2] f6 53 [2] f4 52 [2] ef 54 [2] f3 53 [2] ef 7c }

  condition:
    any of them
}