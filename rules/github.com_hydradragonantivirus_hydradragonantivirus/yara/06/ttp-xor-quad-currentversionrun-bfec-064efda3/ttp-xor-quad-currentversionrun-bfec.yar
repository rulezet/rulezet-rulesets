rule TTP_XOR_QUAD_CurrentVersionRun_bfec {
  strings:
    $key_bfec = { ec 83 [2] c8 8d [2] e3 a1 [2] cd 83 [2] d9 98 [2] d6 82 [2] c8 9f [2] ca 9e [2] d1 98 [2] cd 9f [2] d1 b0 }

  condition:
    any of them
}