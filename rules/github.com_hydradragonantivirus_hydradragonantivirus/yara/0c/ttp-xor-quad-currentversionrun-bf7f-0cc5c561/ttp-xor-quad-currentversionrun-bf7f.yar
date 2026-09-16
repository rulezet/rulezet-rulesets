rule TTP_XOR_QUAD_CurrentVersionRun_bf7f {
  strings:
    $key_bf7f = { ec 10 [2] c8 1e [2] e3 32 [2] cd 10 [2] d9 0b [2] d6 11 [2] c8 0c [2] ca 0d [2] d1 0b [2] cd 0c [2] d1 23 }

  condition:
    any of them
}