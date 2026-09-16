rule TTP_XOR_QUAD_CurrentVersionRun_64e4 {
  strings:
    $key_64e4 = { 37 8b [2] 13 85 [2] 38 a9 [2] 16 8b [2] 02 90 [2] 0d 8a [2] 13 97 [2] 11 96 [2] 0a 90 [2] 16 97 [2] 0a b8 }

  condition:
    any of them
}