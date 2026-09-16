rule TTP_XOR_QUAD_CurrentVersionRun_b088 {
  strings:
    $key_b088 = { e3 e7 [2] c7 e9 [2] ec c5 [2] c2 e7 [2] d6 fc [2] d9 e6 [2] c7 fb [2] c5 fa [2] de fc [2] c2 fb [2] de d4 }

  condition:
    any of them
}