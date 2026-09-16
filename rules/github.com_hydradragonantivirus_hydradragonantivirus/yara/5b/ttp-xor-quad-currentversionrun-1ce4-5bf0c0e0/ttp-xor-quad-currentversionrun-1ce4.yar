rule TTP_XOR_QUAD_CurrentVersionRun_1ce4 {
  strings:
    $key_1ce4 = { 4f 8b [2] 6b 85 [2] 40 a9 [2] 6e 8b [2] 7a 90 [2] 75 8a [2] 6b 97 [2] 69 96 [2] 72 90 [2] 6e 97 [2] 72 b8 }

  condition:
    any of them
}