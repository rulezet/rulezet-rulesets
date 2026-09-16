rule TTP_XOR_QUAD_CurrentVersionRun_2d88 {
  strings:
    $key_2d88 = { 7e e7 [2] 5a e9 [2] 71 c5 [2] 5f e7 [2] 4b fc [2] 44 e6 [2] 5a fb [2] 58 fa [2] 43 fc [2] 5f fb [2] 43 d4 }

  condition:
    any of them
}