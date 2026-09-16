rule TTP_XOR_QUAD_CurrentVersionRun_bf56 {
  strings:
    $key_bf56 = { ec 39 [2] c8 37 [2] e3 1b [2] cd 39 [2] d9 22 [2] d6 38 [2] c8 25 [2] ca 24 [2] d1 22 [2] cd 25 [2] d1 0a }

  condition:
    any of them
}