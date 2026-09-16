rule TTP_XOR_QUAD_CurrentVersionRun_bf4d {
  strings:
    $key_bf4d = { ec 22 [2] c8 2c [2] e3 00 [2] cd 22 [2] d9 39 [2] d6 23 [2] c8 3e [2] ca 3f [2] d1 39 [2] cd 3e [2] d1 11 }

  condition:
    any of them
}