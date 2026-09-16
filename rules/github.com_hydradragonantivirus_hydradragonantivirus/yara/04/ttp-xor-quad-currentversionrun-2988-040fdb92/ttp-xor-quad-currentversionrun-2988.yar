rule TTP_XOR_QUAD_CurrentVersionRun_2988 {
  strings:
    $key_2988 = { 7a e7 [2] 5e e9 [2] 75 c5 [2] 5b e7 [2] 4f fc [2] 40 e6 [2] 5e fb [2] 5c fa [2] 47 fc [2] 5b fb [2] 47 d4 }

  condition:
    any of them
}