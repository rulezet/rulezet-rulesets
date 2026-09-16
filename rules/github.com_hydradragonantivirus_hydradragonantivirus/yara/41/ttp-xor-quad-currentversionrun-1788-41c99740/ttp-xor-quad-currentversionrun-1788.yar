rule TTP_XOR_QUAD_CurrentVersionRun_1788 {
  strings:
    $key_1788 = { 44 e7 [2] 60 e9 [2] 4b c5 [2] 65 e7 [2] 71 fc [2] 7e e6 [2] 60 fb [2] 62 fa [2] 79 fc [2] 65 fb [2] 79 d4 }

  condition:
    any of them
}