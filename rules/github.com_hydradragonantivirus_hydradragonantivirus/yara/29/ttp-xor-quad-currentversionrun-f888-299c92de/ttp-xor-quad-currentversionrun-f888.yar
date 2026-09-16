rule TTP_XOR_QUAD_CurrentVersionRun_f888 {
  strings:
    $key_f888 = { ab e7 [2] 8f e9 [2] a4 c5 [2] 8a e7 [2] 9e fc [2] 91 e6 [2] 8f fb [2] 8d fa [2] 96 fc [2] 8a fb [2] 96 d4 }

  condition:
    any of them
}