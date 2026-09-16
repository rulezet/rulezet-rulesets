rule TTP_XOR_QUAD_CurrentVersionRun_ba67 {
  strings:
    $key_ba67 = { e9 08 [2] cd 06 [2] e6 2a [2] c8 08 [2] dc 13 [2] d3 09 [2] cd 14 [2] cf 15 [2] d4 13 [2] c8 14 [2] d4 3b }

  condition:
    any of them
}