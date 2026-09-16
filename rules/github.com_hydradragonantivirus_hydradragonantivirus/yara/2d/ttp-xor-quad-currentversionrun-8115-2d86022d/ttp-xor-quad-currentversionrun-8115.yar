rule TTP_XOR_QUAD_CurrentVersionRun_8115 {
  strings:
    $key_8115 = { d2 7a [2] f6 74 [2] dd 58 [2] f3 7a [2] e7 61 [2] e8 7b [2] f6 66 [2] f4 67 [2] ef 61 [2] f3 66 [2] ef 49 }

  condition:
    any of them
}