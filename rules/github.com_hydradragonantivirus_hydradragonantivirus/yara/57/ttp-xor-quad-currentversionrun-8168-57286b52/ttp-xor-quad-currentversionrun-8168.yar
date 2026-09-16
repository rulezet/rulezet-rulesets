rule TTP_XOR_QUAD_CurrentVersionRun_8168 {
  strings:
    $key_8168 = { d2 07 [2] f6 09 [2] dd 25 [2] f3 07 [2] e7 1c [2] e8 06 [2] f6 1b [2] f4 1a [2] ef 1c [2] f3 1b [2] ef 34 }

  condition:
    any of them
}