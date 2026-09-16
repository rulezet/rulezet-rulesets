rule TTP_XOR_QUAD_CurrentVersionRun_2de4 {
  strings:
    $key_2de4 = { 7e 8b [2] 5a 85 [2] 71 a9 [2] 5f 8b [2] 4b 90 [2] 44 8a [2] 5a 97 [2] 58 96 [2] 43 90 [2] 5f 97 [2] 43 b8 }

  condition:
    any of them
}