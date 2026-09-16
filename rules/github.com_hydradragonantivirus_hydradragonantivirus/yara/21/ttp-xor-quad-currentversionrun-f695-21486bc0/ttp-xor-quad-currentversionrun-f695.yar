rule TTP_XOR_QUAD_CurrentVersionRun_f695 {
  strings:
    $key_f695 = { a5 fa [2] 81 f4 [2] aa d8 [2] 84 fa [2] 90 e1 [2] 9f fb [2] 81 e6 [2] 83 e7 [2] 98 e1 [2] 84 e6 [2] 98 c9 }

  condition:
    any of them
}