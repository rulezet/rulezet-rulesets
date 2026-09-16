rule TTP_XOR_QUAD_CurrentVersionRun_1988 {
  strings:
    $key_1988 = { 4a e7 [2] 6e e9 [2] 45 c5 [2] 6b e7 [2] 7f fc [2] 70 e6 [2] 6e fb [2] 6c fa [2] 77 fc [2] 6b fb [2] 77 d4 }

  condition:
    any of them
}