rule TTP_XOR_QUAD_CurrentVersionRun_4d69 {
  strings:
    $key_4d69 = { 1e 06 [2] 3a 08 [2] 11 24 [2] 3f 06 [2] 2b 1d [2] 24 07 [2] 3a 1a [2] 38 1b [2] 23 1d [2] 3f 1a [2] 23 35 }

  condition:
    any of them
}