rule TTP_XOR_QUAD_CurrentVersionRun_bae4 {
  strings:
    $key_bae4 = { e9 8b [2] cd 85 [2] e6 a9 [2] c8 8b [2] dc 90 [2] d3 8a [2] cd 97 [2] cf 96 [2] d4 90 [2] c8 97 [2] d4 b8 }

  condition:
    any of them
}