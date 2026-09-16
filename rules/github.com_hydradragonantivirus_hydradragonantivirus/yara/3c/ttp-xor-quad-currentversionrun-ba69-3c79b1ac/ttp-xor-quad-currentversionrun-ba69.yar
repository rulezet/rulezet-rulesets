rule TTP_XOR_QUAD_CurrentVersionRun_ba69 {
  strings:
    $key_ba69 = { e9 06 [2] cd 08 [2] e6 24 [2] c8 06 [2] dc 1d [2] d3 07 [2] cd 1a [2] cf 1b [2] d4 1d [2] c8 1a [2] d4 35 }

  condition:
    any of them
}