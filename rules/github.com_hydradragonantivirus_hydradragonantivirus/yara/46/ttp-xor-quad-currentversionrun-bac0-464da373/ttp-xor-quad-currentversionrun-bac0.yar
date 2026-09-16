rule TTP_XOR_QUAD_CurrentVersionRun_bac0 {
  strings:
    $key_bac0 = { e9 af [2] cd a1 [2] e6 8d [2] c8 af [2] dc b4 [2] d3 ae [2] cd b3 [2] cf b2 [2] d4 b4 [2] c8 b3 [2] d4 9c }

  condition:
    any of them
}