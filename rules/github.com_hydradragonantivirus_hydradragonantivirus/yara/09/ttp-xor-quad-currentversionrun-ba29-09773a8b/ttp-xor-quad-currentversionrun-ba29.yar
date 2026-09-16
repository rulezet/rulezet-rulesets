rule TTP_XOR_QUAD_CurrentVersionRun_ba29 {
  strings:
    $key_ba29 = { e9 46 [2] cd 48 [2] e6 64 [2] c8 46 [2] dc 5d [2] d3 47 [2] cd 5a [2] cf 5b [2] d4 5d [2] c8 5a [2] d4 75 }

  condition:
    any of them
}