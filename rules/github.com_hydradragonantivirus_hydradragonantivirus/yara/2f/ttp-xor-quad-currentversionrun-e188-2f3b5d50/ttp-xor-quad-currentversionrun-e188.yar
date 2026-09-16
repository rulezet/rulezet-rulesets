rule TTP_XOR_QUAD_CurrentVersionRun_e188 {
  strings:
    $key_e188 = { b2 e7 [2] 96 e9 [2] bd c5 [2] 93 e7 [2] 87 fc [2] 88 e6 [2] 96 fb [2] 94 fa [2] 8f fc [2] 93 fb [2] 8f d4 }

  condition:
    any of them
}