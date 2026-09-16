rule TTP_XOR_QUAD_CurrentVersionRun_ba45 {
  strings:
    $key_ba45 = { e9 2a [2] cd 24 [2] e6 08 [2] c8 2a [2] dc 31 [2] d3 2b [2] cd 36 [2] cf 37 [2] d4 31 [2] c8 36 [2] d4 19 }

  condition:
    any of them
}