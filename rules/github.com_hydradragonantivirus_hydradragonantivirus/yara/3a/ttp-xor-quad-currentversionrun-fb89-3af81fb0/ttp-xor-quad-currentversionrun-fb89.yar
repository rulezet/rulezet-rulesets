rule TTP_XOR_QUAD_CurrentVersionRun_fb89 {
  strings:
    $key_fb89 = { a8 e6 [2] 8c e8 [2] a7 c4 [2] 89 e6 [2] 9d fd [2] 92 e7 [2] 8c fa [2] 8e fb [2] 95 fd [2] 89 fa [2] 95 d5 }

  condition:
    any of them
}