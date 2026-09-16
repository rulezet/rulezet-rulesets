rule TTP_XOR_QUAD_CurrentVersionRun_7688 {
  strings:
    $key_7688 = { 25 e7 [2] 01 e9 [2] 2a c5 [2] 04 e7 [2] 10 fc [2] 1f e6 [2] 01 fb [2] 03 fa [2] 18 fc [2] 04 fb [2] 18 d4 }

  condition:
    any of them
}