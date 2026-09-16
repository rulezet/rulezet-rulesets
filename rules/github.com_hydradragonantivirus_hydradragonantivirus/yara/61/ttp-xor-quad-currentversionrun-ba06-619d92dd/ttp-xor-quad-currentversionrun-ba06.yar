rule TTP_XOR_QUAD_CurrentVersionRun_ba06 {
  strings:
    $key_ba06 = { e9 69 [2] cd 67 [2] e6 4b [2] c8 69 [2] dc 72 [2] d3 68 [2] cd 75 [2] cf 74 [2] d4 72 [2] c8 75 [2] d4 5a }

  condition:
    any of them
}