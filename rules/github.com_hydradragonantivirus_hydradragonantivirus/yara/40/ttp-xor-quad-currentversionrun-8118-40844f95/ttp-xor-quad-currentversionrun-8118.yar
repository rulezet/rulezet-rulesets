rule TTP_XOR_QUAD_CurrentVersionRun_8118 {
  strings:
    $key_8118 = { d2 77 [2] f6 79 [2] dd 55 [2] f3 77 [2] e7 6c [2] e8 76 [2] f6 6b [2] f4 6a [2] ef 6c [2] f3 6b [2] ef 44 }

  condition:
    any of them
}