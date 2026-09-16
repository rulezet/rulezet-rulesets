rule TTP_XOR_QUAD_CurrentVersionRun_ba74 {
  strings:
    $key_ba74 = { e9 1b [2] cd 15 [2] e6 39 [2] c8 1b [2] dc 00 [2] d3 1a [2] cd 07 [2] cf 06 [2] d4 00 [2] c8 07 [2] d4 28 }

  condition:
    any of them
}