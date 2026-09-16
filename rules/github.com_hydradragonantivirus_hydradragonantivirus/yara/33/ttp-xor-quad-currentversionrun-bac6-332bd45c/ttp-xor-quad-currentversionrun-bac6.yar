rule TTP_XOR_QUAD_CurrentVersionRun_bac6 {
  strings:
    $key_bac6 = { e9 a9 [2] cd a7 [2] e6 8b [2] c8 a9 [2] dc b2 [2] d3 a8 [2] cd b5 [2] cf b4 [2] d4 b2 [2] c8 b5 [2] d4 9a }

  condition:
    any of them
}