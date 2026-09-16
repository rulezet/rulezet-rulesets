rule TTP_XOR_QUAD_CurrentVersionRun_7588 {
  strings:
    $key_7588 = { 26 e7 [2] 02 e9 [2] 29 c5 [2] 07 e7 [2] 13 fc [2] 1c e6 [2] 02 fb [2] 00 fa [2] 1b fc [2] 07 fb [2] 1b d4 }

  condition:
    any of them
}