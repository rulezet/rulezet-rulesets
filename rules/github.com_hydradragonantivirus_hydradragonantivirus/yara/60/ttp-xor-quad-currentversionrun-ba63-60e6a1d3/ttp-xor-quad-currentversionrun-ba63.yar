rule TTP_XOR_QUAD_CurrentVersionRun_ba63 {
  strings:
    $key_ba63 = { e9 0c [2] cd 02 [2] e6 2e [2] c8 0c [2] dc 17 [2] d3 0d [2] cd 10 [2] cf 11 [2] d4 17 [2] c8 10 [2] d4 3f }

  condition:
    any of them
}