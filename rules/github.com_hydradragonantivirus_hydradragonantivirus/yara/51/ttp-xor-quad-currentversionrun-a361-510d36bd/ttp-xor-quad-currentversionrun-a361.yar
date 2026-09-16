rule TTP_XOR_QUAD_CurrentVersionRun_a361 {
  strings:
    $key_a361 = { f0 0e [2] d4 00 [2] ff 2c [2] d1 0e [2] c5 15 [2] ca 0f [2] d4 12 [2] d6 13 [2] cd 15 [2] d1 12 [2] cd 3d }

  condition:
    any of them
}