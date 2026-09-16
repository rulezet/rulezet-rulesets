rule TTP_XOR_QUAD_CurrentVersionRun_1e88 {
  strings:
    $key_1e88 = { 4d e7 [2] 69 e9 [2] 42 c5 [2] 6c e7 [2] 78 fc [2] 77 e6 [2] 69 fb [2] 6b fa [2] 70 fc [2] 6c fb [2] 70 d4 }

  condition:
    any of them
}