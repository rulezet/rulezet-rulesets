rule TTP_XOR_QUAD_CurrentVersionRun_baf5 {
  strings:
    $key_baf5 = { e9 9a [2] cd 94 [2] e6 b8 [2] c8 9a [2] dc 81 [2] d3 9b [2] cd 86 [2] cf 87 [2] d4 81 [2] c8 86 [2] d4 a9 }

  condition:
    any of them
}