rule TTP_XOR_QUAD_CurrentVersionRun_8176 {
  strings:
    $key_8176 = { d2 19 [2] f6 17 [2] dd 3b [2] f3 19 [2] e7 02 [2] e8 18 [2] f6 05 [2] f4 04 [2] ef 02 [2] f3 05 [2] ef 2a }

  condition:
    any of them
}