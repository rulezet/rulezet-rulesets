rule TTP_XOR_QUAD_CurrentVersionRun_a3f5 {
  strings:
    $key_a3f5 = { f0 9a [2] d4 94 [2] ff b8 [2] d1 9a [2] c5 81 [2] ca 9b [2] d4 86 [2] d6 87 [2] cd 81 [2] d1 86 [2] cd a9 }

  condition:
    any of them
}