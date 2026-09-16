rule TTP_XOR_QUAD_CurrentVersionRun_a33e {
  strings:
    $key_a33e = { f0 51 [2] d4 5f [2] ff 73 [2] d1 51 [2] c5 4a [2] ca 50 [2] d4 4d [2] d6 4c [2] cd 4a [2] d1 4d [2] cd 62 }

  condition:
    any of them
}