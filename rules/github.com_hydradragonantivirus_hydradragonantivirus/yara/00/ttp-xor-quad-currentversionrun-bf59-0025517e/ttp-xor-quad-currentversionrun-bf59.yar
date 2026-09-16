rule TTP_XOR_QUAD_CurrentVersionRun_bf59 {
  strings:
    $key_bf59 = { ec 36 [2] c8 38 [2] e3 14 [2] cd 36 [2] d9 2d [2] d6 37 [2] c8 2a [2] ca 2b [2] d1 2d [2] cd 2a [2] d1 05 }

  condition:
    any of them
}