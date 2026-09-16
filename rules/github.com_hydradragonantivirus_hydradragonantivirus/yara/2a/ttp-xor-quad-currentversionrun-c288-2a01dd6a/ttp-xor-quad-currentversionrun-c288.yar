rule TTP_XOR_QUAD_CurrentVersionRun_c288 {
  strings:
    $key_c288 = { 91 e7 [2] b5 e9 [2] 9e c5 [2] b0 e7 [2] a4 fc [2] ab e6 [2] b5 fb [2] b7 fa [2] ac fc [2] b0 fb [2] ac d4 }

  condition:
    any of them
}