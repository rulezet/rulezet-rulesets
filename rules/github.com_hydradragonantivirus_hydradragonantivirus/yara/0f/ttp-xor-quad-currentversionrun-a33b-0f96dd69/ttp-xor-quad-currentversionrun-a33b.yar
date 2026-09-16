rule TTP_XOR_QUAD_CurrentVersionRun_a33b {
  strings:
    $key_a33b = { f0 54 [2] d4 5a [2] ff 76 [2] d1 54 [2] c5 4f [2] ca 55 [2] d4 48 [2] d6 49 [2] cd 4f [2] d1 48 [2] cd 67 }

  condition:
    any of them
}