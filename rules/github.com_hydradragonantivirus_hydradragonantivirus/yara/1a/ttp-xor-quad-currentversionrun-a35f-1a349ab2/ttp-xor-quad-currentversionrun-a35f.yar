rule TTP_XOR_QUAD_CurrentVersionRun_a35f {
  strings:
    $key_a35f = { f0 30 [2] d4 3e [2] ff 12 [2] d1 30 [2] c5 2b [2] ca 31 [2] d4 2c [2] d6 2d [2] cd 2b [2] d1 2c [2] cd 03 }

  condition:
    any of them
}