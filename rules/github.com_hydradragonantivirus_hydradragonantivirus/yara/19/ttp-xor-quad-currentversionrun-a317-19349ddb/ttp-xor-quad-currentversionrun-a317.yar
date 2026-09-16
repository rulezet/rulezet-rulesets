rule TTP_XOR_QUAD_CurrentVersionRun_a317 {
  strings:
    $key_a317 = { f0 78 [2] d4 76 [2] ff 5a [2] d1 78 [2] c5 63 [2] ca 79 [2] d4 64 [2] d6 65 [2] cd 63 [2] d1 64 [2] cd 4b }

  condition:
    any of them
}