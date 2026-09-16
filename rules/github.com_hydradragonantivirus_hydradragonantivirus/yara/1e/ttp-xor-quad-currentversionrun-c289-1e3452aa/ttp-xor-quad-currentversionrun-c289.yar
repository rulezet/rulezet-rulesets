rule TTP_XOR_QUAD_CurrentVersionRun_c289 {
  strings:
    $key_c289 = { 91 e6 [2] b5 e8 [2] 9e c4 [2] b0 e6 [2] a4 fd [2] ab e7 [2] b5 fa [2] b7 fb [2] ac fd [2] b0 fa [2] ac d5 }

  condition:
    any of them
}