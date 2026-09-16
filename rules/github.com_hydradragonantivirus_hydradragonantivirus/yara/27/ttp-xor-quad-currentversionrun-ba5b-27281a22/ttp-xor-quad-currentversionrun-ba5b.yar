rule TTP_XOR_QUAD_CurrentVersionRun_ba5b {
  strings:
    $key_ba5b = { e9 34 [2] cd 3a [2] e6 16 [2] c8 34 [2] dc 2f [2] d3 35 [2] cd 28 [2] cf 29 [2] d4 2f [2] c8 28 [2] d4 07 }

  condition:
    any of them
}