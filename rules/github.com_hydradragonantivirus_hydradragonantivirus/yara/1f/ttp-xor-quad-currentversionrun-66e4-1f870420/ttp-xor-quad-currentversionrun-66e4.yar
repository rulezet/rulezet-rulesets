rule TTP_XOR_QUAD_CurrentVersionRun_66e4 {
  strings:
    $key_66e4 = { 35 8b [2] 11 85 [2] 3a a9 [2] 14 8b [2] 00 90 [2] 0f 8a [2] 11 97 [2] 13 96 [2] 08 90 [2] 14 97 [2] 08 b8 }

  condition:
    any of them
}