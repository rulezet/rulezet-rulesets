rule TTP_XOR_QUAD_CurrentVersionRun_bf54 {
  strings:
    $key_bf54 = { ec 3b [2] c8 35 [2] e3 19 [2] cd 3b [2] d9 20 [2] d6 3a [2] c8 27 [2] ca 26 [2] d1 20 [2] cd 27 [2] d1 08 }

  condition:
    any of them
}