rule TTP_XOR_QUAD_CurrentVersionRun_8138 {
  strings:
    $key_8138 = { d2 57 [2] f6 59 [2] dd 75 [2] f3 57 [2] e7 4c [2] e8 56 [2] f6 4b [2] f4 4a [2] ef 4c [2] f3 4b [2] ef 64 }

  condition:
    any of them
}