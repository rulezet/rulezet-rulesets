rule TTP_XOR_QUAD_CurrentVersionRun_c094 {
  strings:
    $key_c094 = { 93 fb [2] b7 f5 [2] 9c d9 [2] b2 fb [2] a6 e0 [2] a9 fa [2] b7 e7 [2] b5 e6 [2] ae e0 [2] b2 e7 [2] ae c8 }

  condition:
    any of them
}