rule TTP_XOR_QUAD_CurrentVersionRun_d087 {
  strings:
    $key_d087 = { 83 e8 [2] a7 e6 [2] 8c ca [2] a2 e8 [2] b6 f3 [2] b9 e9 [2] a7 f4 [2] a5 f5 [2] be f3 [2] a2 f4 [2] be db }

  condition:
    any of them
}