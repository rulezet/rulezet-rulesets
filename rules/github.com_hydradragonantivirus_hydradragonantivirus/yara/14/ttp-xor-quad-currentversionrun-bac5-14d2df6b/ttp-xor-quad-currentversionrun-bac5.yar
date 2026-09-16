rule TTP_XOR_QUAD_CurrentVersionRun_bac5 {
  strings:
    $key_bac5 = { e9 aa [2] cd a4 [2] e6 88 [2] c8 aa [2] dc b1 [2] d3 ab [2] cd b6 [2] cf b7 [2] d4 b1 [2] c8 b6 [2] d4 99 }

  condition:
    any of them
}