rule TTP_XOR_QUAD_CurrentVersionRun_d288 {
  strings:
    $key_d288 = { 81 e7 [2] a5 e9 [2] 8e c5 [2] a0 e7 [2] b4 fc [2] bb e6 [2] a5 fb [2] a7 fa [2] bc fc [2] a0 fb [2] bc d4 }

  condition:
    any of them
}