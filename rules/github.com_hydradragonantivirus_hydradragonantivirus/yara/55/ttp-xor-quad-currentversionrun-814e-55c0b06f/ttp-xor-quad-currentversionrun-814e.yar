rule TTP_XOR_QUAD_CurrentVersionRun_814e {
  strings:
    $key_814e = { d2 21 [2] f6 2f [2] dd 03 [2] f3 21 [2] e7 3a [2] e8 20 [2] f6 3d [2] f4 3c [2] ef 3a [2] f3 3d [2] ef 12 }

  condition:
    any of them
}