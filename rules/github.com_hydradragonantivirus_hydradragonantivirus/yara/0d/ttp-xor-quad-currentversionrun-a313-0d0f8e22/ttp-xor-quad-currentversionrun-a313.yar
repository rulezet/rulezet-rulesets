rule TTP_XOR_QUAD_CurrentVersionRun_a313 {
  strings:
    $key_a313 = { f0 7c [2] d4 72 [2] ff 5e [2] d1 7c [2] c5 67 [2] ca 7d [2] d4 60 [2] d6 61 [2] cd 67 [2] d1 60 [2] cd 4f }

  condition:
    any of them
}