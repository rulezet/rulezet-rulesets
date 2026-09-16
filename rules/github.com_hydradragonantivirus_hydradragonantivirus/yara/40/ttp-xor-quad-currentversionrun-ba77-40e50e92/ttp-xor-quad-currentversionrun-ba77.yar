rule TTP_XOR_QUAD_CurrentVersionRun_ba77 {
  strings:
    $key_ba77 = { e9 18 [2] cd 16 [2] e6 3a [2] c8 18 [2] dc 03 [2] d3 19 [2] cd 04 [2] cf 05 [2] d4 03 [2] c8 04 [2] d4 2b }

  condition:
    any of them
}