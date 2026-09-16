rule TTP_XOR_QUAD_CurrentVersionRun_a35c {
  strings:
    $key_a35c = { f0 33 [2] d4 3d [2] ff 11 [2] d1 33 [2] c5 28 [2] ca 32 [2] d4 2f [2] d6 2e [2] cd 28 [2] d1 2f [2] cd 00 }

  condition:
    any of them
}