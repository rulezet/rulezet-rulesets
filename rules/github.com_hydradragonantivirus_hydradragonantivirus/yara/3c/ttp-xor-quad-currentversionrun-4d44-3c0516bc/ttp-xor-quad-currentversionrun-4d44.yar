rule TTP_XOR_QUAD_CurrentVersionRun_4d44 {
  strings:
    $key_4d44 = { 1e 2b [2] 3a 25 [2] 11 09 [2] 3f 2b [2] 2b 30 [2] 24 2a [2] 3a 37 [2] 38 36 [2] 23 30 [2] 3f 37 [2] 23 18 }

  condition:
    any of them
}