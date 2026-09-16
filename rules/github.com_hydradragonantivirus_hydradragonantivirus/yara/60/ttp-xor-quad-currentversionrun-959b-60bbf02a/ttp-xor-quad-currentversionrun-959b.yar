rule TTP_XOR_QUAD_CurrentVersionRun_959b {
  strings:
    $key_959b = { c6 f4 [2] e2 fa [2] c9 d6 [2] e7 f4 [2] f3 ef [2] fc f5 [2] e2 e8 [2] e0 e9 [2] fb ef [2] e7 e8 [2] fb c7 }

  condition:
    any of them
}