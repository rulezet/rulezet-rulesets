rule TTP_XOR_QUAD_CurrentVersionRun_bf5d {
  strings:
    $key_bf5d = { ec 32 [2] c8 3c [2] e3 10 [2] cd 32 [2] d9 29 [2] d6 33 [2] c8 2e [2] ca 2f [2] d1 29 [2] cd 2e [2] d1 01 }

  condition:
    any of them
}