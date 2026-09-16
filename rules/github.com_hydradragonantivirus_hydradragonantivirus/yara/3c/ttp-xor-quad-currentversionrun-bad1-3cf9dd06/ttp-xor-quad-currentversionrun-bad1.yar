rule TTP_XOR_QUAD_CurrentVersionRun_bad1 {
  strings:
    $key_bad1 = { e9 be [2] cd b0 [2] e6 9c [2] c8 be [2] dc a5 [2] d3 bf [2] cd a2 [2] cf a3 [2] d4 a5 [2] c8 a2 [2] d4 8d }

  condition:
    any of them
}