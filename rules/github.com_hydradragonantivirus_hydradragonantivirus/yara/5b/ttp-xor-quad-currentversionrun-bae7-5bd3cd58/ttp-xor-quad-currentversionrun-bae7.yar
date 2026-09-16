rule TTP_XOR_QUAD_CurrentVersionRun_bae7 {
  strings:
    $key_bae7 = { e9 88 [2] cd 86 [2] e6 aa [2] c8 88 [2] dc 93 [2] d3 89 [2] cd 94 [2] cf 95 [2] d4 93 [2] c8 94 [2] d4 bb }

  condition:
    any of them
}