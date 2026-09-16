rule TTP_XOR_QUAD_CurrentVersionRun_e094 {
  strings:
    $key_e094 = { b3 fb [2] 97 f5 [2] bc d9 [2] 92 fb [2] 86 e0 [2] 89 fa [2] 97 e7 [2] 95 e6 [2] 8e e0 [2] 92 e7 [2] 8e c8 }

  condition:
    any of them
}