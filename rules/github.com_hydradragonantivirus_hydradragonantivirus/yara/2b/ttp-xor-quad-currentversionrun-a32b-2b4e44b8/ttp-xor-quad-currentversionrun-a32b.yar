rule TTP_XOR_QUAD_CurrentVersionRun_a32b {
  strings:
    $key_a32b = { f0 44 [2] d4 4a [2] ff 66 [2] d1 44 [2] c5 5f [2] ca 45 [2] d4 58 [2] d6 59 [2] cd 5f [2] d1 58 [2] cd 77 }

  condition:
    any of them
}