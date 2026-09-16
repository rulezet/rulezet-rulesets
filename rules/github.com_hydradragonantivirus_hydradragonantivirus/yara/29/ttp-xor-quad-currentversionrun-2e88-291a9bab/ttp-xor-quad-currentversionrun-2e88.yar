rule TTP_XOR_QUAD_CurrentVersionRun_2e88 {
  strings:
    $key_2e88 = { 7d e7 [2] 59 e9 [2] 72 c5 [2] 5c e7 [2] 48 fc [2] 47 e6 [2] 59 fb [2] 5b fa [2] 40 fc [2] 5c fb [2] 40 d4 }

  condition:
    any of them
}