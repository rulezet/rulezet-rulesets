rule TTP_XOR_QUAD_CurrentVersionRun_8137 {
  strings:
    $key_8137 = { d2 58 [2] f6 56 [2] dd 7a [2] f3 58 [2] e7 43 [2] e8 59 [2] f6 44 [2] f4 45 [2] ef 43 [2] f3 44 [2] ef 6b }

  condition:
    any of them
}