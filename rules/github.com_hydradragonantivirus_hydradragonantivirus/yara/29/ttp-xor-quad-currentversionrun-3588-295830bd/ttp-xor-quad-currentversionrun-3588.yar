rule TTP_XOR_QUAD_CurrentVersionRun_3588 {
  strings:
    $key_3588 = { 66 e7 [2] 42 e9 [2] 69 c5 [2] 47 e7 [2] 53 fc [2] 5c e6 [2] 42 fb [2] 40 fa [2] 5b fc [2] 47 fb [2] 5b d4 }

  condition:
    any of them
}