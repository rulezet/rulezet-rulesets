rule TTP_XOR_QUAD_CurrentVersionRun_ba70 {
  strings:
    $key_ba70 = { e9 1f [2] cd 11 [2] e6 3d [2] c8 1f [2] dc 04 [2] d3 1e [2] cd 03 [2] cf 02 [2] d4 04 [2] c8 03 [2] d4 2c }

  condition:
    any of them
}