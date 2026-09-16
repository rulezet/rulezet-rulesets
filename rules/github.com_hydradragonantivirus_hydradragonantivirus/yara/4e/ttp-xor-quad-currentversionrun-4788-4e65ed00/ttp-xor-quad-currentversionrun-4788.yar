rule TTP_XOR_QUAD_CurrentVersionRun_4788 {
  strings:
    $key_4788 = { 14 e7 [2] 30 e9 [2] 1b c5 [2] 35 e7 [2] 21 fc [2] 2e e6 [2] 30 fb [2] 32 fa [2] 29 fc [2] 35 fb [2] 29 d4 }

  condition:
    any of them
}