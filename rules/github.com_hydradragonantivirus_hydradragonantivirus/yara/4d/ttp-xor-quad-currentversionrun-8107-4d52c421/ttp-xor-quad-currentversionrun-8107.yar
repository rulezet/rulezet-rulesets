rule TTP_XOR_QUAD_CurrentVersionRun_8107 {
  strings:
    $key_8107 = { d2 68 [2] f6 66 [2] dd 4a [2] f3 68 [2] e7 73 [2] e8 69 [2] f6 74 [2] f4 75 [2] ef 73 [2] f3 74 [2] ef 5b }

  condition:
    any of them
}