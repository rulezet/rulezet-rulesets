rule TTP_XOR_QUAD_CurrentVersionRun_eea5 {
  strings:
    $key_eea5 = { bd ca [2] 99 c4 [2] b2 e8 [2] 9c ca [2] 88 d1 [2] 87 cb [2] 99 d6 [2] 9b d7 [2] 80 d1 [2] 9c d6 [2] 80 f9 }

  condition:
    any of them
}