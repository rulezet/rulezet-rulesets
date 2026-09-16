rule TTP_XOR_QUAD_CurrentVersionRun_bad7 {
  strings:
    $key_bad7 = { e9 b8 [2] cd b6 [2] e6 9a [2] c8 b8 [2] dc a3 [2] d3 b9 [2] cd a4 [2] cf a5 [2] d4 a3 [2] c8 a4 [2] d4 8b }

  condition:
    any of them
}