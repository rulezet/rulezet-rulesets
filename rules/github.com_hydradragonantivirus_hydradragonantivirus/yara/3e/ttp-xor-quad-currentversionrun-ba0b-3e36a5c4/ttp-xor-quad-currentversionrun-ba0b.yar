rule TTP_XOR_QUAD_CurrentVersionRun_ba0b {
  strings:
    $key_ba0b = { e9 64 [2] cd 6a [2] e6 46 [2] c8 64 [2] dc 7f [2] d3 65 [2] cd 78 [2] cf 79 [2] d4 7f [2] c8 78 [2] d4 57 }

  condition:
    any of them
}