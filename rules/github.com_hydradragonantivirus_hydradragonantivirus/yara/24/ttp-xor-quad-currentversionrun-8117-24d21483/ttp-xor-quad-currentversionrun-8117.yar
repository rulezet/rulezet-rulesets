rule TTP_XOR_QUAD_CurrentVersionRun_8117 {
  strings:
    $key_8117 = { d2 78 [2] f6 76 [2] dd 5a [2] f3 78 [2] e7 63 [2] e8 79 [2] f6 64 [2] f4 65 [2] ef 63 [2] f3 64 [2] ef 4b }

  condition:
    any of them
}