rule TTP_XOR_QUAD_CurrentVersionRun_0d88 {
  strings:
    $key_0d88 = { 5e e7 [2] 7a e9 [2] 51 c5 [2] 7f e7 [2] 6b fc [2] 64 e6 [2] 7a fb [2] 78 fa [2] 63 fc [2] 7f fb [2] 63 d4 }

  condition:
    any of them
}