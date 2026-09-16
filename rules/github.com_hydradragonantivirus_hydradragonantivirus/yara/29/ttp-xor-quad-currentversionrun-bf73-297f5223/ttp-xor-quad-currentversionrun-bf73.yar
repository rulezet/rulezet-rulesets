rule TTP_XOR_QUAD_CurrentVersionRun_bf73 {
  strings:
    $key_bf73 = { ec 1c [2] c8 12 [2] e3 3e [2] cd 1c [2] d9 07 [2] d6 1d [2] c8 00 [2] ca 01 [2] d1 07 [2] cd 00 [2] d1 2f }

  condition:
    any of them
}