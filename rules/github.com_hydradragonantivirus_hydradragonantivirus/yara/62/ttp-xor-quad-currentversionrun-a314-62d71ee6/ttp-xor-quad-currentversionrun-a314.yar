rule TTP_XOR_QUAD_CurrentVersionRun_a314 {
  strings:
    $key_a314 = { f0 7b [2] d4 75 [2] ff 59 [2] d1 7b [2] c5 60 [2] ca 7a [2] d4 67 [2] d6 66 [2] cd 60 [2] d1 67 [2] cd 48 }

  condition:
    any of them
}