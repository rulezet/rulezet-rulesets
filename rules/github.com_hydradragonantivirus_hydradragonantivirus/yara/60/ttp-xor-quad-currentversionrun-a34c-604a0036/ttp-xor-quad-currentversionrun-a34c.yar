rule TTP_XOR_QUAD_CurrentVersionRun_a34c {
  strings:
    $key_a34c = { f0 23 [2] d4 2d [2] ff 01 [2] d1 23 [2] c5 38 [2] ca 22 [2] d4 3f [2] d6 3e [2] cd 38 [2] d1 3f [2] cd 10 }

  condition:
    any of them
}