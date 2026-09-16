rule TTP_XOR_QUAD_CurrentVersionRun_04e4 {
  strings:
    $key_04e4 = { 57 8b [2] 73 85 [2] 58 a9 [2] 76 8b [2] 62 90 [2] 6d 8a [2] 73 97 [2] 71 96 [2] 6a 90 [2] 76 97 [2] 6a b8 }

  condition:
    any of them
}