rule TTP_XOR_QUAD_CurrentVersionRun_a30d {
  strings:
    $key_a30d = { f0 62 [2] d4 6c [2] ff 40 [2] d1 62 [2] c5 79 [2] ca 63 [2] d4 7e [2] d6 7f [2] cd 79 [2] d1 7e [2] cd 51 }

  condition:
    any of them
}