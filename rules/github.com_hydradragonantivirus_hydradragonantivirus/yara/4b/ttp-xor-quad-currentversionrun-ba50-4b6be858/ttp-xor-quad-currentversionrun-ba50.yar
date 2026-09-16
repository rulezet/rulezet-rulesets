rule TTP_XOR_QUAD_CurrentVersionRun_ba50 {
  strings:
    $key_ba50 = { e9 3f [2] cd 31 [2] e6 1d [2] c8 3f [2] dc 24 [2] d3 3e [2] cd 23 [2] cf 22 [2] d4 24 [2] c8 23 [2] d4 0c }

  condition:
    any of them
}