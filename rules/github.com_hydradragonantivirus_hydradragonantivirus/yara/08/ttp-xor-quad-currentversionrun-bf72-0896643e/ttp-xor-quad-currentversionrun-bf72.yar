rule TTP_XOR_QUAD_CurrentVersionRun_bf72 {
  strings:
    $key_bf72 = { ec 1d [2] c8 13 [2] e3 3f [2] cd 1d [2] d9 06 [2] d6 1c [2] c8 01 [2] ca 00 [2] d1 06 [2] cd 01 [2] d1 2e }

  condition:
    any of them
}