rule TTP_XOR_QUAD_CurrentVersionRun_bf69 {
  strings:
    $key_bf69 = { ec 06 [2] c8 08 [2] e3 24 [2] cd 06 [2] d9 1d [2] d6 07 [2] c8 1a [2] ca 1b [2] d1 1d [2] cd 1a [2] d1 35 }

  condition:
    any of them
}