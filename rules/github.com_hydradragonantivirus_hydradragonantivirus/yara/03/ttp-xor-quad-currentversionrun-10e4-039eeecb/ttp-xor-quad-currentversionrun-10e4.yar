rule TTP_XOR_QUAD_CurrentVersionRun_10e4 {
  strings:
    $key_10e4 = { 43 8b [2] 67 85 [2] 4c a9 [2] 62 8b [2] 76 90 [2] 79 8a [2] 67 97 [2] 65 96 [2] 7e 90 [2] 62 97 [2] 7e b8 }

  condition:
    any of them
}