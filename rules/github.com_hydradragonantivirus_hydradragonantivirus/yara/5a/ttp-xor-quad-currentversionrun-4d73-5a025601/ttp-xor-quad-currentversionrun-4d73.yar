rule TTP_XOR_QUAD_CurrentVersionRun_4d73 {
  strings:
    $key_4d73 = { 1e 1c [2] 3a 12 [2] 11 3e [2] 3f 1c [2] 2b 07 [2] 24 1d [2] 3a 00 [2] 38 01 [2] 23 07 [2] 3f 00 [2] 23 2f }

  condition:
    any of them
}