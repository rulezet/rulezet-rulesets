rule TTP_XOR_QUAD_CurrentVersionRun_1aa5 {
  strings:
    $key_1aa5 = { 49 ca [2] 6d c4 [2] 46 e8 [2] 68 ca [2] 7c d1 [2] 73 cb [2] 6d d6 [2] 6f d7 [2] 74 d1 [2] 68 d6 [2] 74 f9 }

  condition:
    any of them
}