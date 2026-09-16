rule TTP_XOR_QUAD_CurrentVersionRun_fea5 {
  strings:
    $key_fea5 = { ad ca [2] 89 c4 [2] a2 e8 [2] 8c ca [2] 98 d1 [2] 97 cb [2] 89 d6 [2] 8b d7 [2] 90 d1 [2] 8c d6 [2] 90 f9 }

  condition:
    any of them
}