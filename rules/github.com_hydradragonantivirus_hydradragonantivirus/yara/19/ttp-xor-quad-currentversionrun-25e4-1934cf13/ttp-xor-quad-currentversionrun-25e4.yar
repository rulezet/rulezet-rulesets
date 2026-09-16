rule TTP_XOR_QUAD_CurrentVersionRun_25e4 {
  strings:
    $key_25e4 = { 76 8b [2] 52 85 [2] 79 a9 [2] 57 8b [2] 43 90 [2] 4c 8a [2] 52 97 [2] 50 96 [2] 4b 90 [2] 57 97 [2] 4b b8 }

  condition:
    any of them
}