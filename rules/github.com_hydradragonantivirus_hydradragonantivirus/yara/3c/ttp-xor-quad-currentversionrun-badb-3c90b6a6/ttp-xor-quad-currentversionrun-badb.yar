rule TTP_XOR_QUAD_CurrentVersionRun_badb {
  strings:
    $key_badb = { e9 b4 [2] cd ba [2] e6 96 [2] c8 b4 [2] dc af [2] d3 b5 [2] cd a8 [2] cf a9 [2] d4 af [2] c8 a8 [2] d4 87 }

  condition:
    any of them
}