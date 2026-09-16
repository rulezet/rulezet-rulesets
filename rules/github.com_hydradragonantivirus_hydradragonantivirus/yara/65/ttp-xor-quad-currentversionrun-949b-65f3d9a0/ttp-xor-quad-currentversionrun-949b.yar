rule TTP_XOR_QUAD_CurrentVersionRun_949b {
  strings:
    $key_949b = { c7 f4 [2] e3 fa [2] c8 d6 [2] e6 f4 [2] f2 ef [2] fd f5 [2] e3 e8 [2] e1 e9 [2] fa ef [2] e6 e8 [2] fa c7 }

  condition:
    any of them
}