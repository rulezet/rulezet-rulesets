rule TTP_XOR_QUAD_CurrentVersionRun_1288 {
  strings:
    $key_1288 = { 41 e7 [2] 65 e9 [2] 4e c5 [2] 60 e7 [2] 74 fc [2] 7b e6 [2] 65 fb [2] 67 fa [2] 7c fc [2] 60 fb [2] 7c d4 }

  condition:
    any of them
}