rule TTP_XOR_QUAD_CurrentVersionRun_a339 {
  strings:
    $key_a339 = { f0 56 [2] d4 58 [2] ff 74 [2] d1 56 [2] c5 4d [2] ca 57 [2] d4 4a [2] d6 4b [2] cd 4d [2] d1 4a [2] cd 65 }

  condition:
    any of them
}