rule TTP_XOR_QUAD_CurrentVersionRun_a37b {
  strings:
    $key_a37b = { f0 14 [2] d4 1a [2] ff 36 [2] d1 14 [2] c5 0f [2] ca 15 [2] d4 08 [2] d6 09 [2] cd 0f [2] d1 08 [2] cd 27 }

  condition:
    any of them
}