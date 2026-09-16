rule TTP_XOR_QUAD_CurrentVersionRun_c588 {
  strings:
    $key_c588 = { 96 e7 [2] b2 e9 [2] 99 c5 [2] b7 e7 [2] a3 fc [2] ac e6 [2] b2 fb [2] b0 fa [2] ab fc [2] b7 fb [2] ab d4 }

  condition:
    any of them
}