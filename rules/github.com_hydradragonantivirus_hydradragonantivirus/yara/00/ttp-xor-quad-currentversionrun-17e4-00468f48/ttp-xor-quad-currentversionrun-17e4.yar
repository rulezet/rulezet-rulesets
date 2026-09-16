rule TTP_XOR_QUAD_CurrentVersionRun_17e4 {
  strings:
    $key_17e4 = { 44 8b [2] 60 85 [2] 4b a9 [2] 65 8b [2] 71 90 [2] 7e 8a [2] 60 97 [2] 62 96 [2] 79 90 [2] 65 97 [2] 79 b8 }

  condition:
    any of them
}