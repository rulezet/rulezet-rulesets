rule TTP_XOR_QUAD_CurrentVersionRun_a321 {
  strings:
    $key_a321 = { f0 4e [2] d4 40 [2] ff 6c [2] d1 4e [2] c5 55 [2] ca 4f [2] d4 52 [2] d6 53 [2] cd 55 [2] d1 52 [2] cd 7d }

  condition:
    any of them
}