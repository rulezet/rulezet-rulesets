rule TTP_XOR_QUAD_CurrentVersionRun_a3fc {
  strings:
    $key_a3fc = { f0 93 [2] d4 9d [2] ff b1 [2] d1 93 [2] c5 88 [2] ca 92 [2] d4 8f [2] d6 8e [2] cd 88 [2] d1 8f [2] cd a0 }

  condition:
    any of them
}