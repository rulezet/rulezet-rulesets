rule TTP_XOR_QUAD_CurrentVersionRun_4d64 {
  strings:
    $key_4d64 = { 1e 0b [2] 3a 05 [2] 11 29 [2] 3f 0b [2] 2b 10 [2] 24 0a [2] 3a 17 [2] 38 16 [2] 23 10 [2] 3f 17 [2] 23 38 }

  condition:
    any of them
}