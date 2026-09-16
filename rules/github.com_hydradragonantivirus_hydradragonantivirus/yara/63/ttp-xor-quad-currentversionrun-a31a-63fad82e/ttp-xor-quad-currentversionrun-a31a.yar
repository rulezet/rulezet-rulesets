rule TTP_XOR_QUAD_CurrentVersionRun_a31a {
  strings:
    $key_a31a = { f0 75 [2] d4 7b [2] ff 57 [2] d1 75 [2] c5 6e [2] ca 74 [2] d4 69 [2] d6 68 [2] cd 6e [2] d1 69 [2] cd 46 }

  condition:
    any of them
}