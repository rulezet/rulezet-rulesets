rule TTP_XOR_QUAD_CurrentVersionRun_ba37 {
  strings:
    $key_ba37 = { e9 58 [2] cd 56 [2] e6 7a [2] c8 58 [2] dc 43 [2] d3 59 [2] cd 44 [2] cf 45 [2] d4 43 [2] c8 44 [2] d4 6b }

  condition:
    any of them
}