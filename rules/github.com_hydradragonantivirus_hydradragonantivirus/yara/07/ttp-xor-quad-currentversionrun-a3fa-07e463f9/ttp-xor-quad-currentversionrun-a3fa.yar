rule TTP_XOR_QUAD_CurrentVersionRun_a3fa {
  strings:
    $key_a3fa = { f0 95 [2] d4 9b [2] ff b7 [2] d1 95 [2] c5 8e [2] ca 94 [2] d4 89 [2] d6 88 [2] cd 8e [2] d1 89 [2] cd a6 }

  condition:
    any of them
}