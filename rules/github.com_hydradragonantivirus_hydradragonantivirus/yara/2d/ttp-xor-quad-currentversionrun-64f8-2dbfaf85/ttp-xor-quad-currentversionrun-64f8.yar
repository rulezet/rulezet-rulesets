rule TTP_XOR_QUAD_CurrentVersionRun_64f8 {
  strings:
    $key_64f8 = { 37 97 [2] 13 99 [2] 38 b5 [2] 16 97 [2] 02 8c [2] 0d 96 [2] 13 8b [2] 11 8a [2] 0a 8c [2] 16 8b [2] 0a a4 }

  condition:
    any of them
}