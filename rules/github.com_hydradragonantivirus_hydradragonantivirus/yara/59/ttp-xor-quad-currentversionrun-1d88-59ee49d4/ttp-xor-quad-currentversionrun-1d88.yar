rule TTP_XOR_QUAD_CurrentVersionRun_1d88 {
  strings:
    $key_1d88 = { 4e e7 [2] 6a e9 [2] 41 c5 [2] 6f e7 [2] 7b fc [2] 74 e6 [2] 6a fb [2] 68 fa [2] 73 fc [2] 6f fb [2] 73 d4 }

  condition:
    any of them
}