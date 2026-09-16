rule TTP_XOR_QUAD_CurrentVersionRun_36e4 {
  strings:
    $key_36e4 = { 65 8b [2] 41 85 [2] 6a a9 [2] 44 8b [2] 50 90 [2] 5f 8a [2] 41 97 [2] 43 96 [2] 58 90 [2] 44 97 [2] 58 b8 }

  condition:
    any of them
}