rule TTP_XOR_QUAD_CurrentVersionRun_f188 {
  strings:
    $key_f188 = { a2 e7 [2] 86 e9 [2] ad c5 [2] 83 e7 [2] 97 fc [2] 98 e6 [2] 86 fb [2] 84 fa [2] 9f fc [2] 83 fb [2] 9f d4 }

  condition:
    any of them
}