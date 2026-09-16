rule TTP_XOR_QUAD_CurrentVersionRun_abc6 {
  strings:
    $key_abc6 = { f8 a9 [2] dc a7 [2] f7 8b [2] d9 a9 [2] cd b2 [2] c2 a8 [2] dc b5 [2] de b4 [2] c5 b2 [2] d9 b5 [2] c5 9a }

  condition:
    any of them
}