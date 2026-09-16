rule TTP_XOR_QUAD_CurrentVersionRun_ba56 {
  strings:
    $key_ba56 = { e9 39 [2] cd 37 [2] e6 1b [2] c8 39 [2] dc 22 [2] d3 38 [2] cd 25 [2] cf 24 [2] d4 22 [2] c8 25 [2] d4 0a }

  condition:
    any of them
}