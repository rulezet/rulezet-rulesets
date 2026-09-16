rule TTP_XOR_QUAD_CurrentVersionRun_bfed {
  strings:
    $key_bfed = { ec 82 [2] c8 8c [2] e3 a0 [2] cd 82 [2] d9 99 [2] d6 83 [2] c8 9e [2] ca 9f [2] d1 99 [2] cd 9e [2] d1 b1 }

  condition:
    any of them
}