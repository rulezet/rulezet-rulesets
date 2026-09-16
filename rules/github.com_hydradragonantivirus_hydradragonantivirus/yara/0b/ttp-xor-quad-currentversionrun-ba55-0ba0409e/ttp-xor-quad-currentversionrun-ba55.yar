rule TTP_XOR_QUAD_CurrentVersionRun_ba55 {
  strings:
    $key_ba55 = { e9 3a [2] cd 34 [2] e6 18 [2] c8 3a [2] dc 21 [2] d3 3b [2] cd 26 [2] cf 27 [2] d4 21 [2] c8 26 [2] d4 09 }

  condition:
    any of them
}