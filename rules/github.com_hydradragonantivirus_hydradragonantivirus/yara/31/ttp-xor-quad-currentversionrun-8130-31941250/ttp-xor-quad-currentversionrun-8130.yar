rule TTP_XOR_QUAD_CurrentVersionRun_8130 {
  strings:
    $key_8130 = { d2 5f [2] f6 51 [2] dd 7d [2] f3 5f [2] e7 44 [2] e8 5e [2] f6 43 [2] f4 42 [2] ef 44 [2] f3 43 [2] ef 6c }

  condition:
    any of them
}