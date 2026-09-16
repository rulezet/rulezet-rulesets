rule TTP_XOR_QUAD_CurrentVersionRun_a3ec {
  strings:
    $key_a3ec = { f0 83 [2] d4 8d [2] ff a1 [2] d1 83 [2] c5 98 [2] ca 82 [2] d4 9f [2] d6 9e [2] cd 98 [2] d1 9f [2] cd b0 }

  condition:
    any of them
}