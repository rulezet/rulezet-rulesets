rule TTP_XOR_QUAD_CurrentVersionRun_ba44 {
  strings:
    $key_ba44 = { e9 2b [2] cd 25 [2] e6 09 [2] c8 2b [2] dc 30 [2] d3 2a [2] cd 37 [2] cf 36 [2] d4 30 [2] c8 37 [2] d4 18 }

  condition:
    any of them
}