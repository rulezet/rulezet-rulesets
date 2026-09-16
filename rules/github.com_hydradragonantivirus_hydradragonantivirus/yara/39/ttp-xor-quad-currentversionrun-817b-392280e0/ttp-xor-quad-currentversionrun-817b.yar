rule TTP_XOR_QUAD_CurrentVersionRun_817b {
  strings:
    $key_817b = { d2 14 [2] f6 1a [2] dd 36 [2] f3 14 [2] e7 0f [2] e8 15 [2] f6 08 [2] f4 09 [2] ef 0f [2] f3 08 [2] ef 27 }

  condition:
    any of them
}