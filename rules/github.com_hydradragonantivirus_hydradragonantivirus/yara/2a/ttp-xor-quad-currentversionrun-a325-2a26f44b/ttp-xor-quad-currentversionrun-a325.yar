rule TTP_XOR_QUAD_CurrentVersionRun_a325 {
  strings:
    $key_a325 = { f0 4a [2] d4 44 [2] ff 68 [2] d1 4a [2] c5 51 [2] ca 4b [2] d4 56 [2] d6 57 [2] cd 51 [2] d1 56 [2] cd 79 }

  condition:
    any of them
}