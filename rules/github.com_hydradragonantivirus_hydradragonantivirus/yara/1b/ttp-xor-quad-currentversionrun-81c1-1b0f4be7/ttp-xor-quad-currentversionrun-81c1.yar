rule TTP_XOR_QUAD_CurrentVersionRun_81c1 {
  strings:
    $key_81c1 = { d2 ae [2] f6 a0 [2] dd 8c [2] f3 ae [2] e7 b5 [2] e8 af [2] f6 b2 [2] f4 b3 [2] ef b5 [2] f3 b2 [2] ef 9d }

  condition:
    any of them
}