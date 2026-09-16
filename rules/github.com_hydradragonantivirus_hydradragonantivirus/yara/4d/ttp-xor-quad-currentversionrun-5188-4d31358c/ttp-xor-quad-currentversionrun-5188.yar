rule TTP_XOR_QUAD_CurrentVersionRun_5188 {
  strings:
    $key_5188 = { 02 e7 [2] 26 e9 [2] 0d c5 [2] 23 e7 [2] 37 fc [2] 38 e6 [2] 26 fb [2] 24 fa [2] 3f fc [2] 23 fb [2] 3f d4 }

  condition:
    any of them
}