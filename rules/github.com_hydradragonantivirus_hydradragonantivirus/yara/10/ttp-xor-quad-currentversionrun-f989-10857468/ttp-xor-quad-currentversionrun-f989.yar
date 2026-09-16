rule TTP_XOR_QUAD_CurrentVersionRun_f989 {
  strings:
    $key_f989 = { aa e6 [2] 8e e8 [2] a5 c4 [2] 8b e6 [2] 9f fd [2] 90 e7 [2] 8e fa [2] 8c fb [2] 97 fd [2] 8b fa [2] 97 d5 }

  condition:
    any of them
}