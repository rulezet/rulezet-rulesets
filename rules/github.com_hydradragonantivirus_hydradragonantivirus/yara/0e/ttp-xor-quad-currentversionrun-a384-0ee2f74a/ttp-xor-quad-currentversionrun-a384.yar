rule TTP_XOR_QUAD_CurrentVersionRun_a384 {
  strings:
    $key_a384 = { f0 eb [2] d4 e5 [2] ff c9 [2] d1 eb [2] c5 f0 [2] ca ea [2] d4 f7 [2] d6 f6 [2] cd f0 [2] d1 f7 [2] cd d8 }

  condition:
    any of them
}