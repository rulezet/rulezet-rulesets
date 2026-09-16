rule TTP_XOR_QUAD_CurrentVersionRun_86c1 {
  strings:
    $key_86c1 = { d5 ae [2] f1 a0 [2] da 8c [2] f4 ae [2] e0 b5 [2] ef af [2] f1 b2 [2] f3 b3 [2] e8 b5 [2] f4 b2 [2] e8 9d }

  condition:
    any of them
}