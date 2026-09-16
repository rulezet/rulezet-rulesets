rule TTP_XOR_QUAD_CurrentVersionRun_5de4 {
  strings:
    $key_5de4 = { 0e 8b [2] 2a 85 [2] 01 a9 [2] 2f 8b [2] 3b 90 [2] 34 8a [2] 2a 97 [2] 28 96 [2] 33 90 [2] 2f 97 [2] 33 b8 }

  condition:
    any of them
}