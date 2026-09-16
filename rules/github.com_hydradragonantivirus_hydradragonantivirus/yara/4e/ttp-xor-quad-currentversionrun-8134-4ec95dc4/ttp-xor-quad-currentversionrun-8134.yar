rule TTP_XOR_QUAD_CurrentVersionRun_8134 {
  strings:
    $key_8134 = { d2 5b [2] f6 55 [2] dd 79 [2] f3 5b [2] e7 40 [2] e8 5a [2] f6 47 [2] f4 46 [2] ef 40 [2] f3 47 [2] ef 68 }

  condition:
    any of them
}