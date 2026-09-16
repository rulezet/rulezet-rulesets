rule TTP_XOR_QUAD_CurrentVersionRun_f988 {
  strings:
    $key_f988 = { aa e7 [2] 8e e9 [2] a5 c5 [2] 8b e7 [2] 9f fc [2] 90 e6 [2] 8e fb [2] 8c fa [2] 97 fc [2] 8b fb [2] 97 d4 }

  condition:
    any of them
}