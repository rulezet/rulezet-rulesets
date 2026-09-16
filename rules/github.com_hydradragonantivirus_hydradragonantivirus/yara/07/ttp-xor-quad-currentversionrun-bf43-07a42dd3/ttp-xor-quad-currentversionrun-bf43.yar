rule TTP_XOR_QUAD_CurrentVersionRun_bf43 {
  strings:
    $key_bf43 = { ec 2c [2] c8 22 [2] e3 0e [2] cd 2c [2] d9 37 [2] d6 2d [2] c8 30 [2] ca 31 [2] d1 37 [2] cd 30 [2] d1 1f }

  condition:
    any of them
}