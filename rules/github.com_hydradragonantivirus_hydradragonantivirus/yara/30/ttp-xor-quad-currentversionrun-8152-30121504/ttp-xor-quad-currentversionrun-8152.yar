rule TTP_XOR_QUAD_CurrentVersionRun_8152 {
  strings:
    $key_8152 = { d2 3d [2] f6 33 [2] dd 1f [2] f3 3d [2] e7 26 [2] e8 3c [2] f6 21 [2] f4 20 [2] ef 26 [2] f3 21 [2] ef 0e }

  condition:
    any of them
}