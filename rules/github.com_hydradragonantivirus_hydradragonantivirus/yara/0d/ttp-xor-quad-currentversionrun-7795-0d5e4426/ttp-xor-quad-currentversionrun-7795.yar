rule TTP_XOR_QUAD_CurrentVersionRun_7795 {
  strings:
    $key_7795 = { 24 fa [2] 00 f4 [2] 2b d8 [2] 05 fa [2] 11 e1 [2] 1e fb [2] 00 e6 [2] 02 e7 [2] 19 e1 [2] 05 e6 [2] 19 c9 }

  condition:
    any of them
}