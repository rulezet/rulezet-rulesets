rule TTP_XOR_QUAD_CurrentVersionRun_d09a {
  strings:
    $key_d09a = { 83 f5 [2] a7 fb [2] 8c d7 [2] a2 f5 [2] b6 ee [2] b9 f4 [2] a7 e9 [2] a5 e8 [2] be ee [2] a2 e9 [2] be c6 }

  condition:
    any of them
}