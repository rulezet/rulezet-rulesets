rule TTP_XOR_QUAD_CurrentVersionRun_a3ea {
  strings:
    $key_a3ea = { f0 85 [2] d4 8b [2] ff a7 [2] d1 85 [2] c5 9e [2] ca 84 [2] d4 99 [2] d6 98 [2] cd 9e [2] d1 99 [2] cd b6 }

  condition:
    any of them
}