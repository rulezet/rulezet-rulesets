rule TTP_XOR_QUAD_CurrentVersionRun_a309 {
  strings:
    $key_a309 = { f0 66 [2] d4 68 [2] ff 44 [2] d1 66 [2] c5 7d [2] ca 67 [2] d4 7a [2] d6 7b [2] cd 7d [2] d1 7a [2] cd 55 }

  condition:
    any of them
}