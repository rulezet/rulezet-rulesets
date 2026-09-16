rule TTP_XOR_QUAD_CurrentVersionRun_dc89 {
  strings:
    $key_dc89 = { 8f e6 [2] ab e8 [2] 80 c4 [2] ae e6 [2] ba fd [2] b5 e7 [2] ab fa [2] a9 fb [2] b2 fd [2] ae fa [2] b2 d5 }

  condition:
    any of them
}