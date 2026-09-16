rule TTP_XOR_QUAD_CurrentVersionRun_a341 {
  strings:
    $key_a341 = { f0 2e [2] d4 20 [2] ff 0c [2] d1 2e [2] c5 35 [2] ca 2f [2] d4 32 [2] d6 33 [2] cd 35 [2] d1 32 [2] cd 1d }

  condition:
    any of them
}