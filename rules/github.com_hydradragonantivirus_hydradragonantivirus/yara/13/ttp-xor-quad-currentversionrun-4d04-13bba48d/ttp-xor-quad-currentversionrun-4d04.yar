rule TTP_XOR_QUAD_CurrentVersionRun_4d04 {
  strings:
    $key_4d04 = { 1e 6b [2] 3a 65 [2] 11 49 [2] 3f 6b [2] 2b 70 [2] 24 6a [2] 3a 77 [2] 38 76 [2] 23 70 [2] 3f 77 [2] 23 58 }

  condition:
    any of them
}