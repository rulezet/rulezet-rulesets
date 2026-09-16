rule TTP_XOR_QUAD_CurrentVersionRun_a37d {
  strings:
    $key_a37d = { f0 12 [2] d4 1c [2] ff 30 [2] d1 12 [2] c5 09 [2] ca 13 [2] d4 0e [2] d6 0f [2] cd 09 [2] d1 0e [2] cd 21 }

  condition:
    any of them
}