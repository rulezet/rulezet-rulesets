rule TTP_XOR_QUAD_CurrentVersionRun_c188 {
  strings:
    $key_c188 = { 92 e7 [2] b6 e9 [2] 9d c5 [2] b3 e7 [2] a7 fc [2] a8 e6 [2] b6 fb [2] b4 fa [2] af fc [2] b3 fb [2] af d4 }

  condition:
    any of them
}