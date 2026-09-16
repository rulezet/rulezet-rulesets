rule TTP_XOR_QUAD_CurrentVersionRun_a30c {
  strings:
    $key_a30c = { f0 63 [2] d4 6d [2] ff 41 [2] d1 63 [2] c5 78 [2] ca 62 [2] d4 7f [2] d6 7e [2] cd 78 [2] d1 7f [2] cd 50 }

  condition:
    any of them
}