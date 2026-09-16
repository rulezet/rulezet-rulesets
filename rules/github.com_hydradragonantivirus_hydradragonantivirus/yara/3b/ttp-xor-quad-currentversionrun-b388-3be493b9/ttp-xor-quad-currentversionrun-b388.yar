rule TTP_XOR_QUAD_CurrentVersionRun_b388 {
  strings:
    $key_b388 = { e0 e7 [2] c4 e9 [2] ef c5 [2] c1 e7 [2] d5 fc [2] da e6 [2] c4 fb [2] c6 fa [2] dd fc [2] c1 fb [2] dd d4 }

  condition:
    any of them
}