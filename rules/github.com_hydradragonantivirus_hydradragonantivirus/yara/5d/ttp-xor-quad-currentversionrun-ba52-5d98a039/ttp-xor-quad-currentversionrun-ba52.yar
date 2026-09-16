rule TTP_XOR_QUAD_CurrentVersionRun_ba52 {
  strings:
    $key_ba52 = { e9 3d [2] cd 33 [2] e6 1f [2] c8 3d [2] dc 26 [2] d3 3c [2] cd 21 [2] cf 20 [2] d4 26 [2] c8 21 [2] d4 0e }

  condition:
    any of them
}