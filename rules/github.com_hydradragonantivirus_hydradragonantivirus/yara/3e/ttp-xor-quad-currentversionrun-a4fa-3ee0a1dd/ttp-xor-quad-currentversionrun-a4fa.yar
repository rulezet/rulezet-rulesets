rule TTP_XOR_QUAD_CurrentVersionRun_a4fa {
  strings:
    $key_a4fa = { f7 95 [2] d3 9b [2] f8 b7 [2] d6 95 [2] c2 8e [2] cd 94 [2] d3 89 [2] d1 88 [2] ca 8e [2] d6 89 [2] ca a6 }

  condition:
    any of them
}