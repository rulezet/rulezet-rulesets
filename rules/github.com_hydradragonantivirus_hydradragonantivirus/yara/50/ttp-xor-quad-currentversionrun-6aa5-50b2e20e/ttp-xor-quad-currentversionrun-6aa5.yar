rule TTP_XOR_QUAD_CurrentVersionRun_6aa5 {
  strings:
    $key_6aa5 = { 39 ca [2] 1d c4 [2] 36 e8 [2] 18 ca [2] 0c d1 [2] 03 cb [2] 1d d6 [2] 1f d7 [2] 04 d1 [2] 18 d6 [2] 04 f9 }

  condition:
    any of them
}