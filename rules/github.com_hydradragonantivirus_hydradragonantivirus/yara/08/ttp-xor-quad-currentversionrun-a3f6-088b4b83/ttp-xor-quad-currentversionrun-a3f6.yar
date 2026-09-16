rule TTP_XOR_QUAD_CurrentVersionRun_a3f6 {
  strings:
    $key_a3f6 = { f0 99 [2] d4 97 [2] ff bb [2] d1 99 [2] c5 82 [2] ca 98 [2] d4 85 [2] d6 84 [2] cd 82 [2] d1 85 [2] cd aa }

  condition:
    any of them
}