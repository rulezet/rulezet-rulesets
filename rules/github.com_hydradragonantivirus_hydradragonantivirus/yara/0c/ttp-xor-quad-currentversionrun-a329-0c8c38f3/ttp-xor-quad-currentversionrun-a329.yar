rule TTP_XOR_QUAD_CurrentVersionRun_a329 {
  strings:
    $key_a329 = { f0 46 [2] d4 48 [2] ff 64 [2] d1 46 [2] c5 5d [2] ca 47 [2] d4 5a [2] d6 5b [2] cd 5d [2] d1 5a [2] cd 75 }

  condition:
    any of them
}