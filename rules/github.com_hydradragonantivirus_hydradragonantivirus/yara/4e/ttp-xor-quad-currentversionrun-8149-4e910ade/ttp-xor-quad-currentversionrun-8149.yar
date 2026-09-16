rule TTP_XOR_QUAD_CurrentVersionRun_8149 {
  strings:
    $key_8149 = { d2 26 [2] f6 28 [2] dd 04 [2] f3 26 [2] e7 3d [2] e8 27 [2] f6 3a [2] f4 3b [2] ef 3d [2] f3 3a [2] ef 15 }

  condition:
    any of them
}