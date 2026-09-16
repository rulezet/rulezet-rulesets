rule TTP_XOR_QUAD_CurrentVersionRun_0988 {
  strings:
    $key_0988 = { 5a e7 [2] 7e e9 [2] 55 c5 [2] 7b e7 [2] 6f fc [2] 60 e6 [2] 7e fb [2] 7c fa [2] 67 fc [2] 7b fb [2] 67 d4 }

  condition:
    any of them
}