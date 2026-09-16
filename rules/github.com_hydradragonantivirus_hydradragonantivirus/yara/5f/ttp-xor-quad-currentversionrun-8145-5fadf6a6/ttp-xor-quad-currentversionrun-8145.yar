rule TTP_XOR_QUAD_CurrentVersionRun_8145 {
  strings:
    $key_8145 = { d2 2a [2] f6 24 [2] dd 08 [2] f3 2a [2] e7 31 [2] e8 2b [2] f6 36 [2] f4 37 [2] ef 31 [2] f3 36 [2] ef 19 }

  condition:
    any of them
}