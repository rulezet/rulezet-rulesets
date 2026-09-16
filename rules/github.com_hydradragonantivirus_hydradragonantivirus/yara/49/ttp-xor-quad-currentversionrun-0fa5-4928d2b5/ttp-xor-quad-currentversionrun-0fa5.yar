rule TTP_XOR_QUAD_CurrentVersionRun_0fa5 {
  strings:
    $key_0fa5 = { 5c ca [2] 78 c4 [2] 53 e8 [2] 7d ca [2] 69 d1 [2] 66 cb [2] 78 d6 [2] 7a d7 [2] 61 d1 [2] 7d d6 [2] 61 f9 }

  condition:
    any of them
}