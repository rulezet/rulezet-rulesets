rule TTP_XOR_QUAD_CurrentVersionRun_baec {
  strings:
    $key_baec = { e9 83 [2] cd 8d [2] e6 a1 [2] c8 83 [2] dc 98 [2] d3 82 [2] cd 9f [2] cf 9e [2] d4 98 [2] c8 9f [2] d4 b0 }

  condition:
    any of them
}