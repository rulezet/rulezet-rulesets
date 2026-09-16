rule TTP_XOR_QUAD_CurrentVersionRun_5588 {
  strings:
    $key_5588 = { 06 e7 [2] 22 e9 [2] 09 c5 [2] 27 e7 [2] 33 fc [2] 3c e6 [2] 22 fb [2] 20 fa [2] 3b fc [2] 27 fb [2] 3b d4 }

  condition:
    any of them
}