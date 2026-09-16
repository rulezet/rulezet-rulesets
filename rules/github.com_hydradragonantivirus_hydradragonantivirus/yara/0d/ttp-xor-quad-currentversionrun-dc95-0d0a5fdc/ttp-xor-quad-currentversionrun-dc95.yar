rule TTP_XOR_QUAD_CurrentVersionRun_dc95 {
  strings:
    $key_dc95 = { 8f fa [2] ab f4 [2] 80 d8 [2] ae fa [2] ba e1 [2] b5 fb [2] ab e6 [2] a9 e7 [2] b2 e1 [2] ae e6 [2] b2 c9 }

  condition:
    any of them
}