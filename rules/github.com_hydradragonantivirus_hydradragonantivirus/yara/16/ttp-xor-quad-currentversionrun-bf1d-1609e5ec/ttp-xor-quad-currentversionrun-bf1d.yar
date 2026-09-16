rule TTP_XOR_QUAD_CurrentVersionRun_bf1d {
  strings:
    $key_bf1d = { ec 72 [2] c8 7c [2] e3 50 [2] cd 72 [2] d9 69 [2] d6 73 [2] c8 6e [2] ca 6f [2] d1 69 [2] cd 6e [2] d1 41 }

  condition:
    any of them
}