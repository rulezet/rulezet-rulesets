rule TTP_XOR_QUAD_CurrentVersionRun_ba7d {
  strings:
    $key_ba7d = { e9 12 [2] cd 1c [2] e6 30 [2] c8 12 [2] dc 09 [2] d3 13 [2] cd 0e [2] cf 0f [2] d4 09 [2] c8 0e [2] d4 21 }

  condition:
    any of them
}