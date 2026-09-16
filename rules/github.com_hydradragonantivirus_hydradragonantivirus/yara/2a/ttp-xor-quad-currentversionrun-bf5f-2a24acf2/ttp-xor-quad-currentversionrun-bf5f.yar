rule TTP_XOR_QUAD_CurrentVersionRun_bf5f {
  strings:
    $key_bf5f = { ec 30 [2] c8 3e [2] e3 12 [2] cd 30 [2] d9 2b [2] d6 31 [2] c8 2c [2] ca 2d [2] d1 2b [2] cd 2c [2] d1 03 }

  condition:
    any of them
}