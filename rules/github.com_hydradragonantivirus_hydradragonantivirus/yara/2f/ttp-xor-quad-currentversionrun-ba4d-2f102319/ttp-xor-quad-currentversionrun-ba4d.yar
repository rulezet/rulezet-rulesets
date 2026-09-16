rule TTP_XOR_QUAD_CurrentVersionRun_ba4d {
  strings:
    $key_ba4d = { e9 22 [2] cd 2c [2] e6 00 [2] c8 22 [2] dc 39 [2] d3 23 [2] cd 3e [2] cf 3f [2] d4 39 [2] c8 3e [2] d4 11 }

  condition:
    any of them
}