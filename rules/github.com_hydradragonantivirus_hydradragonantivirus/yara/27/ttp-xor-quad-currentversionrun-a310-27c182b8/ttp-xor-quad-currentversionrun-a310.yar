rule TTP_XOR_QUAD_CurrentVersionRun_a310 {
  strings:
    $key_a310 = { f0 7f [2] d4 71 [2] ff 5d [2] d1 7f [2] c5 64 [2] ca 7e [2] d4 63 [2] d6 62 [2] cd 64 [2] d1 63 [2] cd 4c }

  condition:
    any of them
}