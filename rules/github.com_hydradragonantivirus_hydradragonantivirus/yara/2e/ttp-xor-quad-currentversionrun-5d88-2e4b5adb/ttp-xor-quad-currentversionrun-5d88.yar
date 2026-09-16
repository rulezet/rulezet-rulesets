rule TTP_XOR_QUAD_CurrentVersionRun_5d88 {
  strings:
    $key_5d88 = { 0e e7 [2] 2a e9 [2] 01 c5 [2] 2f e7 [2] 3b fc [2] 34 e6 [2] 2a fb [2] 28 fa [2] 33 fc [2] 2f fb [2] 33 d4 }

  condition:
    any of them
}