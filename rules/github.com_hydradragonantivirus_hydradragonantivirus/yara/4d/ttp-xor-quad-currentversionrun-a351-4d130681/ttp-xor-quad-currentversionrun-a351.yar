rule TTP_XOR_QUAD_CurrentVersionRun_a351 {
  strings:
    $key_a351 = { f0 3e [2] d4 30 [2] ff 1c [2] d1 3e [2] c5 25 [2] ca 3f [2] d4 22 [2] d6 23 [2] cd 25 [2] d1 22 [2] cd 0d }

  condition:
    any of them
}