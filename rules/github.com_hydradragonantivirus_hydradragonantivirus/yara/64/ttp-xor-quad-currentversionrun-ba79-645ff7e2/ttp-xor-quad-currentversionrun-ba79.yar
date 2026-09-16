rule TTP_XOR_QUAD_CurrentVersionRun_ba79 {
  strings:
    $key_ba79 = { e9 16 [2] cd 18 [2] e6 34 [2] c8 16 [2] dc 0d [2] d3 17 [2] cd 0a [2] cf 0b [2] d4 0d [2] c8 0a [2] d4 25 }

  condition:
    any of them
}