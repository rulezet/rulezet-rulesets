rule TTP_XOR_QUAD_CurrentVersionRun_8e9b {
  strings:
    $key_8e9b = { dd f4 [2] f9 fa [2] d2 d6 [2] fc f4 [2] e8 ef [2] e7 f5 [2] f9 e8 [2] fb e9 [2] e0 ef [2] fc e8 [2] e0 c7 }

  condition:
    any of them
}