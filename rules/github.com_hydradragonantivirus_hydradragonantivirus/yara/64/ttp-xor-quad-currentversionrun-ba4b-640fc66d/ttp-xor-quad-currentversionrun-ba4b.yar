rule TTP_XOR_QUAD_CurrentVersionRun_ba4b {
  strings:
    $key_ba4b = { e9 24 [2] cd 2a [2] e6 06 [2] c8 24 [2] dc 3f [2] d3 25 [2] cd 38 [2] cf 39 [2] d4 3f [2] c8 38 [2] d4 17 }

  condition:
    any of them
}