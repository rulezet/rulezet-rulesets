rule TTP_XOR_QUAD_CurrentVersionRun_ba2c {
  strings:
    $key_ba2c = { e9 43 [2] cd 4d [2] e6 61 [2] c8 43 [2] dc 58 [2] d3 42 [2] cd 5f [2] cf 5e [2] d4 58 [2] c8 5f [2] d4 70 }

  condition:
    any of them
}