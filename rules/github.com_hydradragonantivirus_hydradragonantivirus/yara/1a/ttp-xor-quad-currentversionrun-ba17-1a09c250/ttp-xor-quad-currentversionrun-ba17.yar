rule TTP_XOR_QUAD_CurrentVersionRun_ba17 {
  strings:
    $key_ba17 = { e9 78 [2] cd 76 [2] e6 5a [2] c8 78 [2] dc 63 [2] d3 79 [2] cd 64 [2] cf 65 [2] d4 63 [2] c8 64 [2] d4 4b }

  condition:
    any of them
}