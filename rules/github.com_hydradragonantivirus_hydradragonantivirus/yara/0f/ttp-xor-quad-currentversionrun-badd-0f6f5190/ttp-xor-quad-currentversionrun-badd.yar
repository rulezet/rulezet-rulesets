rule TTP_XOR_QUAD_CurrentVersionRun_badd {
  strings:
    $key_badd = { e9 b2 [2] cd bc [2] e6 90 [2] c8 b2 [2] dc a9 [2] d3 b3 [2] cd ae [2] cf af [2] d4 a9 [2] c8 ae [2] d4 81 }

  condition:
    any of them
}