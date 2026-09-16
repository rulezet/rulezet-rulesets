rule TTP_XOR_QUAD_CurrentVersionRun_ba27 {
  strings:
    $key_ba27 = { e9 48 [2] cd 46 [2] e6 6a [2] c8 48 [2] dc 53 [2] d3 49 [2] cd 54 [2] cf 55 [2] d4 53 [2] c8 54 [2] d4 7b }

  condition:
    any of them
}