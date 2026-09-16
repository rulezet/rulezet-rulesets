rule TTP_XOR_QUAD_CurrentVersionRun_839b {
  strings:
    $key_839b = { d0 f4 [2] f4 fa [2] df d6 [2] f1 f4 [2] e5 ef [2] ea f5 [2] f4 e8 [2] f6 e9 [2] ed ef [2] f1 e8 [2] ed c7 }

  condition:
    any of them
}