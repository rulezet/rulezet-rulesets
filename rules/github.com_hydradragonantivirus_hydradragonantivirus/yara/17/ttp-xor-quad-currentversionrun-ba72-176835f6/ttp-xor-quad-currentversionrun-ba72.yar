rule TTP_XOR_QUAD_CurrentVersionRun_ba72 {
  strings:
    $key_ba72 = { e9 1d [2] cd 13 [2] e6 3f [2] c8 1d [2] dc 06 [2] d3 1c [2] cd 01 [2] cf 00 [2] d4 06 [2] c8 01 [2] d4 2e }

  condition:
    any of them
}