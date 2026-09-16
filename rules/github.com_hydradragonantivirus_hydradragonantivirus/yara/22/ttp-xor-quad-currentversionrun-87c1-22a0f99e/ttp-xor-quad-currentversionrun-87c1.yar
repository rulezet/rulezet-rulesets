rule TTP_XOR_QUAD_CurrentVersionRun_87c1 {
  strings:
    $key_87c1 = { d4 ae [2] f0 a0 [2] db 8c [2] f5 ae [2] e1 b5 [2] ee af [2] f0 b2 [2] f2 b3 [2] e9 b5 [2] f5 b2 [2] e9 9d }

  condition:
    any of them
}