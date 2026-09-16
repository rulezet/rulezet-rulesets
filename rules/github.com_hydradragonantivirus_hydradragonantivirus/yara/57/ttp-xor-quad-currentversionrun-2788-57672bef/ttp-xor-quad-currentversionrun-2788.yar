rule TTP_XOR_QUAD_CurrentVersionRun_2788 {
  strings:
    $key_2788 = { 74 e7 [2] 50 e9 [2] 7b c5 [2] 55 e7 [2] 41 fc [2] 4e e6 [2] 50 fb [2] 52 fa [2] 49 fc [2] 55 fb [2] 49 d4 }

  condition:
    any of them
}