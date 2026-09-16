rule TTP_XOR_QUAD_CurrentVersionRun_bf42 {
  strings:
    $key_bf42 = { ec 2d [2] c8 23 [2] e3 0f [2] cd 2d [2] d9 36 [2] d6 2c [2] c8 31 [2] ca 30 [2] d1 36 [2] cd 31 [2] d1 1e }

  condition:
    any of them
}