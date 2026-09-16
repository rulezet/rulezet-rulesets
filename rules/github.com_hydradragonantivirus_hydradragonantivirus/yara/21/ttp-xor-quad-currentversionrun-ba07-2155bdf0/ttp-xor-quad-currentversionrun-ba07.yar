rule TTP_XOR_QUAD_CurrentVersionRun_ba07 {
  strings:
    $key_ba07 = { e9 68 [2] cd 66 [2] e6 4a [2] c8 68 [2] dc 73 [2] d3 69 [2] cd 74 [2] cf 75 [2] d4 73 [2] c8 74 [2] d4 5b }

  condition:
    any of them
}