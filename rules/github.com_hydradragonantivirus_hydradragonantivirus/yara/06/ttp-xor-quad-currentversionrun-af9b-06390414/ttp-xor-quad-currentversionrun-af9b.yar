rule TTP_XOR_QUAD_CurrentVersionRun_af9b {
  strings:
    $key_af9b = { fc f4 [2] d8 fa [2] f3 d6 [2] dd f4 [2] c9 ef [2] c6 f5 [2] d8 e8 [2] da e9 [2] c1 ef [2] dd e8 [2] c1 c7 }

  condition:
    any of them
}