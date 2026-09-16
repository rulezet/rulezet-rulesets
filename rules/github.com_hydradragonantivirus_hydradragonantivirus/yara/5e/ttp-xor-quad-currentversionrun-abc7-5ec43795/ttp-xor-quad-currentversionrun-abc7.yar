rule TTP_XOR_QUAD_CurrentVersionRun_abc7 {
  strings:
    $key_abc7 = { f8 a8 [2] dc a6 [2] f7 8a [2] d9 a8 [2] cd b3 [2] c2 a9 [2] dc b4 [2] de b5 [2] c5 b3 [2] d9 b4 [2] c5 9b }

  condition:
    any of them
}