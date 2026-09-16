rule TTP_XOR_QUAD_CurrentVersionRun_8136 {
  strings:
    $key_8136 = { d2 59 [2] f6 57 [2] dd 7b [2] f3 59 [2] e7 42 [2] e8 58 [2] f6 45 [2] f4 44 [2] ef 42 [2] f3 45 [2] ef 6a }

  condition:
    any of them
}