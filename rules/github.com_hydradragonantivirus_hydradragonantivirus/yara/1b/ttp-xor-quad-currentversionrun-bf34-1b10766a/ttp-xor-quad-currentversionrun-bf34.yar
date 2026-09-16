rule TTP_XOR_QUAD_CurrentVersionRun_bf34 {
  strings:
    $key_bf34 = { ec 5b [2] c8 55 [2] e3 79 [2] cd 5b [2] d9 40 [2] d6 5a [2] c8 47 [2] ca 46 [2] d1 40 [2] cd 47 [2] d1 68 }

  condition:
    any of them
}