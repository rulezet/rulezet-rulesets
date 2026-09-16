rule TTP_XOR_QUAD_CurrentVersionRun_f694 {
  strings:
    $key_f694 = { a5 fb [2] 81 f5 [2] aa d9 [2] 84 fb [2] 90 e0 [2] 9f fa [2] 81 e7 [2] 83 e6 [2] 98 e0 [2] 84 e7 [2] 98 c8 }

  condition:
    any of them
}