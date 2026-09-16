rule TTP_XOR_QUAD_CurrentVersionRun_ba47 {
  strings:
    $key_ba47 = { e9 28 [2] cd 26 [2] e6 0a [2] c8 28 [2] dc 33 [2] d3 29 [2] cd 34 [2] cf 35 [2] d4 33 [2] c8 34 [2] d4 1b }

  condition:
    any of them
}