rule TTP_XOR_QUAD_CurrentVersionRun_a331 {
  strings:
    $key_a331 = { f0 5e [2] d4 50 [2] ff 7c [2] d1 5e [2] c5 45 [2] ca 5f [2] d4 42 [2] d6 43 [2] cd 45 [2] d1 42 [2] cd 6d }

  condition:
    any of them
}