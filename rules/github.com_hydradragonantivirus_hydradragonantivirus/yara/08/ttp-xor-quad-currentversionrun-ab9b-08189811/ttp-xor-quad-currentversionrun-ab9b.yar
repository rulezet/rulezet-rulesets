rule TTP_XOR_QUAD_CurrentVersionRun_ab9b {
  strings:
    $key_ab9b = { f8 f4 [2] dc fa [2] f7 d6 [2] d9 f4 [2] cd ef [2] c2 f5 [2] dc e8 [2] de e9 [2] c5 ef [2] d9 e8 [2] c5 c7 }

  condition:
    any of them
}