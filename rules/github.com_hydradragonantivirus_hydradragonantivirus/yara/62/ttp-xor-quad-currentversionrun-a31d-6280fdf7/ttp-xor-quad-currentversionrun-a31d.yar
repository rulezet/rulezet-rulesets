rule TTP_XOR_QUAD_CurrentVersionRun_a31d {
  strings:
    $key_a31d = { f0 72 [2] d4 7c [2] ff 50 [2] d1 72 [2] c5 69 [2] ca 73 [2] d4 6e [2] d6 6f [2] cd 69 [2] d1 6e [2] cd 41 }

  condition:
    any of them
}