rule TTP_XOR_QUAD_CurrentVersionRun_4de4 {
  strings:
    $key_4de4 = { 1e 8b [2] 3a 85 [2] 11 a9 [2] 3f 8b [2] 2b 90 [2] 24 8a [2] 3a 97 [2] 38 96 [2] 23 90 [2] 3f 97 [2] 23 b8 }

  condition:
    any of them
}