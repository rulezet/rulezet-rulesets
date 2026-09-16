rule TTP_XOR_QUAD_CurrentVersionRun_8119 {
  strings:
    $key_8119 = { d2 76 [2] f6 78 [2] dd 54 [2] f3 76 [2] e7 6d [2] e8 77 [2] f6 6a [2] f4 6b [2] ef 6d [2] f3 6a [2] ef 45 }

  condition:
    any of them
}