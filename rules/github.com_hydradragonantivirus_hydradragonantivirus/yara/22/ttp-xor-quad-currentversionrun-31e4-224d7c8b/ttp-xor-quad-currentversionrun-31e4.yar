rule TTP_XOR_QUAD_CurrentVersionRun_31e4 {
  strings:
    $key_31e4 = { 62 8b [2] 46 85 [2] 6d a9 [2] 43 8b [2] 57 90 [2] 58 8a [2] 46 97 [2] 44 96 [2] 5f 90 [2] 43 97 [2] 5f b8 }

  condition:
    any of them
}