rule TTP_XOR_QUAD_CurrentVersionRun_6d88 {
  strings:
    $key_6d88 = { 3e e7 [2] 1a e9 [2] 31 c5 [2] 1f e7 [2] 0b fc [2] 04 e6 [2] 1a fb [2] 18 fa [2] 03 fc [2] 1f fb [2] 03 d4 }

  condition:
    any of them
}