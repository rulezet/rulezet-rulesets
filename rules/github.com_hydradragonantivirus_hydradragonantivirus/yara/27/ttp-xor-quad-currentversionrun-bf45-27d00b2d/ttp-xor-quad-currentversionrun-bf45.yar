rule TTP_XOR_QUAD_CurrentVersionRun_bf45 {
  strings:
    $key_bf45 = { ec 2a [2] c8 24 [2] e3 08 [2] cd 2a [2] d9 31 [2] d6 2b [2] c8 36 [2] ca 37 [2] d1 31 [2] cd 36 [2] d1 19 }

  condition:
    any of them
}