rule TTP_XOR_QUAD_CurrentVersionRun_a340 {
  strings:
    $key_a340 = { f0 2f [2] d4 21 [2] ff 0d [2] d1 2f [2] c5 34 [2] ca 2e [2] d4 33 [2] d6 32 [2] cd 34 [2] d1 33 [2] cd 1c }

  condition:
    any of them
}