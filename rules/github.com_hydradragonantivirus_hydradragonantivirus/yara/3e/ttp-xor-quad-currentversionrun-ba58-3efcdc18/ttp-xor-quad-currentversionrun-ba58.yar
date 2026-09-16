rule TTP_XOR_QUAD_CurrentVersionRun_ba58 {
  strings:
    $key_ba58 = { e9 37 [2] cd 39 [2] e6 15 [2] c8 37 [2] dc 2c [2] d3 36 [2] cd 2b [2] cf 2a [2] d4 2c [2] c8 2b [2] d4 04 }

  condition:
    any of them
}