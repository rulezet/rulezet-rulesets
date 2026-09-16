rule TTP_XOR_QUAD_CurrentVersionRun_e888 {
  strings:
    $key_e888 = { bb e7 [2] 9f e9 [2] b4 c5 [2] 9a e7 [2] 8e fc [2] 81 e6 [2] 9f fb [2] 9d fa [2] 86 fc [2] 9a fb [2] 86 d4 }

  condition:
    any of them
}