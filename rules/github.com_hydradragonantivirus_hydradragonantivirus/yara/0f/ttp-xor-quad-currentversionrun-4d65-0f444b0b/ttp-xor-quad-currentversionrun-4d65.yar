rule TTP_XOR_QUAD_CurrentVersionRun_4d65 {
  strings:
    $key_4d65 = { 1e 0a [2] 3a 04 [2] 11 28 [2] 3f 0a [2] 2b 11 [2] 24 0b [2] 3a 16 [2] 38 17 [2] 23 11 [2] 3f 16 [2] 23 39 }

  condition:
    any of them
}