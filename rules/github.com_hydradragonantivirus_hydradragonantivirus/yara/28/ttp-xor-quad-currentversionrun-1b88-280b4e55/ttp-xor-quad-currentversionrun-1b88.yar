rule TTP_XOR_QUAD_CurrentVersionRun_1b88 {
  strings:
    $key_1b88 = { 48 e7 [2] 6c e9 [2] 47 c5 [2] 69 e7 [2] 7d fc [2] 72 e6 [2] 6c fb [2] 6e fa [2] 75 fc [2] 69 fb [2] 75 d4 }

  condition:
    any of them
}