rule TTP_XOR_QUAD_CurrentVersionRun_a360 {
  strings:
    $key_a360 = { f0 0f [2] d4 01 [2] ff 2d [2] d1 0f [2] c5 14 [2] ca 0e [2] d4 13 [2] d6 12 [2] cd 14 [2] d1 13 [2] cd 3c }

  condition:
    any of them
}