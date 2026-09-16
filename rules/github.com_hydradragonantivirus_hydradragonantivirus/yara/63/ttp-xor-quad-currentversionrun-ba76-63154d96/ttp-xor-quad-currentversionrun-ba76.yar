rule TTP_XOR_QUAD_CurrentVersionRun_ba76 {
  strings:
    $key_ba76 = { e9 19 [2] cd 17 [2] e6 3b [2] c8 19 [2] dc 02 [2] d3 18 [2] cd 05 [2] cf 04 [2] d4 02 [2] c8 05 [2] d4 2a }

  condition:
    any of them
}