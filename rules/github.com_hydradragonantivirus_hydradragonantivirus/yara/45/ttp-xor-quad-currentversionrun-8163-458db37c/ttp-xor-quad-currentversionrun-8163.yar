rule TTP_XOR_QUAD_CurrentVersionRun_8163 {
  strings:
    $key_8163 = { d2 0c [2] f6 02 [2] dd 2e [2] f3 0c [2] e7 17 [2] e8 0d [2] f6 10 [2] f4 11 [2] ef 17 [2] f3 10 [2] ef 3f }

  condition:
    any of them
}