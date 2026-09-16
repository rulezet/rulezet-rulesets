rule TTP_XOR_QUAD_CurrentVersionRun_0e88 {
  strings:
    $key_0e88 = { 5d e7 [2] 79 e9 [2] 52 c5 [2] 7c e7 [2] 68 fc [2] 67 e6 [2] 79 fb [2] 7b fa [2] 60 fc [2] 7c fb [2] 60 d4 }

  condition:
    any of them
}