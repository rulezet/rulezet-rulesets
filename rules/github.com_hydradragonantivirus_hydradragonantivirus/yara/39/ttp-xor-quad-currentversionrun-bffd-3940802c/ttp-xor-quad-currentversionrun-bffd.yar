rule TTP_XOR_QUAD_CurrentVersionRun_bffd {
  strings:
    $key_bffd = { ec 92 [2] c8 9c [2] e3 b0 [2] cd 92 [2] d9 89 [2] d6 93 [2] c8 8e [2] ca 8f [2] d1 89 [2] cd 8e [2] d1 a1 }

  condition:
    any of them
}