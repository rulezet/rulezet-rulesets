rule TTP_XOR_QUAD_CurrentVersionRun_6588 {
  strings:
    $key_6588 = { 36 e7 [2] 12 e9 [2] 39 c5 [2] 17 e7 [2] 03 fc [2] 0c e6 [2] 12 fb [2] 10 fa [2] 0b fc [2] 17 fb [2] 0b d4 }

  condition:
    any of them
}