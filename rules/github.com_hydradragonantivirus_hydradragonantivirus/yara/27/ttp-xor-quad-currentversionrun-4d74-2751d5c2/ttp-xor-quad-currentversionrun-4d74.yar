rule TTP_XOR_QUAD_CurrentVersionRun_4d74 {
  strings:
    $key_4d74 = { 1e 1b [2] 3a 15 [2] 11 39 [2] 3f 1b [2] 2b 00 [2] 24 1a [2] 3a 07 [2] 38 06 [2] 23 00 [2] 3f 07 [2] 23 28 }

  condition:
    any of them
}