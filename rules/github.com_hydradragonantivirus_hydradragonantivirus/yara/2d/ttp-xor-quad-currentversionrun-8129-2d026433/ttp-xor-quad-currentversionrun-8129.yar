rule TTP_XOR_QUAD_CurrentVersionRun_8129 {
  strings:
    $key_8129 = { d2 46 [2] f6 48 [2] dd 64 [2] f3 46 [2] e7 5d [2] e8 47 [2] f6 5a [2] f4 5b [2] ef 5d [2] f3 5a [2] ef 75 }

  condition:
    any of them
}