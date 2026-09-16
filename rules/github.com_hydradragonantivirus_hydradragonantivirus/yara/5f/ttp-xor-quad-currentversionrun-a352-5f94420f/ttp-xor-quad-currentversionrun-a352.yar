rule TTP_XOR_QUAD_CurrentVersionRun_a352 {
  strings:
    $key_a352 = { f0 3d [2] d4 33 [2] ff 1f [2] d1 3d [2] c5 26 [2] ca 3c [2] d4 21 [2] d6 20 [2] cd 26 [2] d1 21 [2] cd 0e }

  condition:
    any of them
}