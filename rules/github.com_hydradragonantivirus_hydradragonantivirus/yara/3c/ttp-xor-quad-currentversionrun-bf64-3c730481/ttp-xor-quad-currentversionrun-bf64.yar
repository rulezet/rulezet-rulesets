rule TTP_XOR_QUAD_CurrentVersionRun_bf64 {
  strings:
    $key_bf64 = { ec 0b [2] c8 05 [2] e3 29 [2] cd 0b [2] d9 10 [2] d6 0a [2] c8 17 [2] ca 16 [2] d1 10 [2] cd 17 [2] d1 38 }

  condition:
    any of them
}