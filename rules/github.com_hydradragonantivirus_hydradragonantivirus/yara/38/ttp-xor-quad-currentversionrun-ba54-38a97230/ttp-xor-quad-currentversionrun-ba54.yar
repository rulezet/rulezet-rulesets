rule TTP_XOR_QUAD_CurrentVersionRun_ba54 {
  strings:
    $key_ba54 = { e9 3b [2] cd 35 [2] e6 19 [2] c8 3b [2] dc 20 [2] d3 3a [2] cd 27 [2] cf 26 [2] d4 20 [2] c8 27 [2] d4 08 }

  condition:
    any of them
}