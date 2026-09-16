rule TTP_XOR_QUAD_CurrentVersionRun_a59b {
  strings:
    $key_a59b = { f6 f4 [2] d2 fa [2] f9 d6 [2] d7 f4 [2] c3 ef [2] cc f5 [2] d2 e8 [2] d0 e9 [2] cb ef [2] d7 e8 [2] cb c7 }

  condition:
    any of them
}