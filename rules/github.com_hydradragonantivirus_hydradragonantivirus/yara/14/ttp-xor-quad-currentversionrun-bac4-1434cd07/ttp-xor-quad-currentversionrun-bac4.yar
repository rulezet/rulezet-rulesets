rule TTP_XOR_QUAD_CurrentVersionRun_bac4 {
  strings:
    $key_bac4 = { e9 ab [2] cd a5 [2] e6 89 [2] c8 ab [2] dc b0 [2] d3 aa [2] cd b7 [2] cf b6 [2] d4 b0 [2] c8 b7 [2] d4 98 }

  condition:
    any of them
}