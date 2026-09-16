rule TTP_XOR_QUAD_CurrentVersionRun_5595 {
  strings:
    $key_5595 = { 06 fa [2] 22 f4 [2] 09 d8 [2] 27 fa [2] 33 e1 [2] 3c fb [2] 22 e6 [2] 20 e7 [2] 3b e1 [2] 27 e6 [2] 3b c9 }

  condition:
    any of them
}