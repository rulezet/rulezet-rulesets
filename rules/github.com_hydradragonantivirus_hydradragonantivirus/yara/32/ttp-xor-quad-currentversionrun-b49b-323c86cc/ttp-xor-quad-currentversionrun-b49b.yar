rule TTP_XOR_QUAD_CurrentVersionRun_b49b {
  strings:
    $key_b49b = { e7 f4 [2] c3 fa [2] e8 d6 [2] c6 f4 [2] d2 ef [2] dd f5 [2] c3 e8 [2] c1 e9 [2] da ef [2] c6 e8 [2] da c7 }

  condition:
    any of them
}