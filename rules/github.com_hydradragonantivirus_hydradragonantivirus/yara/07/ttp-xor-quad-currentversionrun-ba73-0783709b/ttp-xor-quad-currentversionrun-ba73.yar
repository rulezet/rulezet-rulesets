rule TTP_XOR_QUAD_CurrentVersionRun_ba73 {
  strings:
    $key_ba73 = { e9 1c [2] cd 12 [2] e6 3e [2] c8 1c [2] dc 07 [2] d3 1d [2] cd 00 [2] cf 01 [2] d4 07 [2] c8 00 [2] d4 2f }

  condition:
    any of them
}