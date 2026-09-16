rule TTP_XOR_QUAD_CurrentVersionRun_4d66 {
  strings:
    $key_4d66 = { 1e 09 [2] 3a 07 [2] 11 2b [2] 3f 09 [2] 2b 12 [2] 24 08 [2] 3a 15 [2] 38 14 [2] 23 12 [2] 3f 15 [2] 23 3a }

  condition:
    any of them
}