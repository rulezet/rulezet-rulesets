rule TTP_XOR_QUAD_CurrentVersionRun_0cf8 {
  strings:
    $key_0cf8 = { 5f 97 [2] 7b 99 [2] 50 b5 [2] 7e 97 [2] 6a 8c [2] 65 96 [2] 7b 8b [2] 79 8a [2] 62 8c [2] 7e 8b [2] 62 a4 }

  condition:
    any of them
}