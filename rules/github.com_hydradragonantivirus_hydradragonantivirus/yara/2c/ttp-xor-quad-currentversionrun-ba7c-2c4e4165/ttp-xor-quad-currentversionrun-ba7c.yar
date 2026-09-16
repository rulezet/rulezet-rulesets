rule TTP_XOR_QUAD_CurrentVersionRun_ba7c {
  strings:
    $key_ba7c = { e9 13 [2] cd 1d [2] e6 31 [2] c8 13 [2] dc 08 [2] d3 12 [2] cd 0f [2] cf 0e [2] d4 08 [2] c8 0f [2] d4 20 }

  condition:
    any of them
}