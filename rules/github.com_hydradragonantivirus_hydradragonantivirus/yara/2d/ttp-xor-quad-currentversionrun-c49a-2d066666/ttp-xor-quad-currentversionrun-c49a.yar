rule TTP_XOR_QUAD_CurrentVersionRun_c49a {
  strings:
    $key_c49a = { 97 f5 [2] b3 fb [2] 98 d7 [2] b6 f5 [2] a2 ee [2] ad f4 [2] b3 e9 [2] b1 e8 [2] aa ee [2] b6 e9 [2] aa c6 }

  condition:
    any of them
}