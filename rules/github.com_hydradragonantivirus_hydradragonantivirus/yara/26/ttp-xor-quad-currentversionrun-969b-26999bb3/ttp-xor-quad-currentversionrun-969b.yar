rule TTP_XOR_QUAD_CurrentVersionRun_969b {
  strings:
    $key_969b = { c5 f4 [2] e1 fa [2] ca d6 [2] e4 f4 [2] f0 ef [2] ff f5 [2] e1 e8 [2] e3 e9 [2] f8 ef [2] e4 e8 [2] f8 c7 }

  condition:
    any of them
}