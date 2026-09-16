rule TTP_XOR_QUAD_CurrentVersionRun_8123 {
  strings:
    $key_8123 = { d2 4c [2] f6 42 [2] dd 6e [2] f3 4c [2] e7 57 [2] e8 4d [2] f6 50 [2] f4 51 [2] ef 57 [2] f3 50 [2] ef 7f }

  condition:
    any of them
}