rule TTP_XOR_QUAD_CurrentVersionRun_0788 {
  strings:
    $key_0788 = { 54 e7 [2] 70 e9 [2] 5b c5 [2] 75 e7 [2] 61 fc [2] 6e e6 [2] 70 fb [2] 72 fa [2] 69 fc [2] 75 fb [2] 69 d4 }

  condition:
    any of them
}