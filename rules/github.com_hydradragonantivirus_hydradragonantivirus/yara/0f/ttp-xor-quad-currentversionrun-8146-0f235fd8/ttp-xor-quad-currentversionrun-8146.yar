rule TTP_XOR_QUAD_CurrentVersionRun_8146 {
  strings:
    $key_8146 = { d2 29 [2] f6 27 [2] dd 0b [2] f3 29 [2] e7 32 [2] e8 28 [2] f6 35 [2] f4 34 [2] ef 32 [2] f3 35 [2] ef 1a }

  condition:
    any of them
}