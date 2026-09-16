rule TTP_XOR_QUAD_CurrentVersionRun_a3fb {
  strings:
    $key_a3fb = { f0 94 [2] d4 9a [2] ff b6 [2] d1 94 [2] c5 8f [2] ca 95 [2] d4 88 [2] d6 89 [2] cd 8f [2] d1 88 [2] cd a7 }

  condition:
    any of them
}