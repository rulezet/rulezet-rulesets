rule TTP_XOR_QUAD_CurrentVersionRun_ba53 {
  strings:
    $key_ba53 = { e9 3c [2] cd 32 [2] e6 1e [2] c8 3c [2] dc 27 [2] d3 3d [2] cd 20 [2] cf 21 [2] d4 27 [2] c8 20 [2] d4 0f }

  condition:
    any of them
}