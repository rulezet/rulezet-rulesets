rule TTP_XOR_QUAD_CurrentVersionRun_8139 {
  strings:
    $key_8139 = { d2 56 [2] f6 58 [2] dd 74 [2] f3 56 [2] e7 4d [2] e8 57 [2] f6 4a [2] f4 4b [2] ef 4d [2] f3 4a [2] ef 65 }

  condition:
    any of them
}