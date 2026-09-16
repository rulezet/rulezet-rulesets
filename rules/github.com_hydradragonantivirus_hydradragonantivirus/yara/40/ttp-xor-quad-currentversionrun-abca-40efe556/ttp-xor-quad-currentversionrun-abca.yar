rule TTP_XOR_QUAD_CurrentVersionRun_abca {
  strings:
    $key_abca = { f8 a5 [2] dc ab [2] f7 87 [2] d9 a5 [2] cd be [2] c2 a4 [2] dc b9 [2] de b8 [2] c5 be [2] d9 b9 [2] c5 96 }

  condition:
    any of them
}