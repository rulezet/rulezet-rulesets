rule TTP_XOR_QUAD_CurrentVersionRun_a36e {
  strings:
    $key_a36e = { f0 01 [2] d4 0f [2] ff 23 [2] d1 01 [2] c5 1a [2] ca 00 [2] d4 1d [2] d6 1c [2] cd 1a [2] d1 1d [2] cd 32 }

  condition:
    any of them
}