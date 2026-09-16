rule TTP_XOR_QUAD_CurrentVersionRun_56e4 {
  strings:
    $key_56e4 = { 05 8b [2] 21 85 [2] 0a a9 [2] 24 8b [2] 30 90 [2] 3f 8a [2] 21 97 [2] 23 96 [2] 38 90 [2] 24 97 [2] 38 b8 }

  condition:
    any of them
}