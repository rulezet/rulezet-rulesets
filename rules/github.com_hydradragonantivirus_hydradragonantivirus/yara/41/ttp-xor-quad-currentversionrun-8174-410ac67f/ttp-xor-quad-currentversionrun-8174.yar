rule TTP_XOR_QUAD_CurrentVersionRun_8174 {
  strings:
    $key_8174 = { d2 1b [2] f6 15 [2] dd 39 [2] f3 1b [2] e7 00 [2] e8 1a [2] f6 07 [2] f4 06 [2] ef 00 [2] f3 07 [2] ef 28 }

  condition:
    any of them
}