rule TTP_XOR_QUAD_CurrentVersionRun_a34b {
  strings:
    $key_a34b = { f0 24 [2] d4 2a [2] ff 06 [2] d1 24 [2] c5 3f [2] ca 25 [2] d4 38 [2] d6 39 [2] cd 3f [2] d1 38 [2] cd 17 }

  condition:
    any of them
}