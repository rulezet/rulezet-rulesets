rule TTP_XOR_QUAD_CurrentVersionRun_a31b {
  strings:
    $key_a31b = { f0 74 [2] d4 7a [2] ff 56 [2] d1 74 [2] c5 6f [2] ca 75 [2] d4 68 [2] d6 69 [2] cd 6f [2] d1 68 [2] cd 47 }

  condition:
    any of them
}