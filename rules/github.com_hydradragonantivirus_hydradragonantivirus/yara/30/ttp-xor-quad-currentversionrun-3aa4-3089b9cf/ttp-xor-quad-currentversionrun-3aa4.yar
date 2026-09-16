rule TTP_XOR_QUAD_CurrentVersionRun_3aa4 {
  strings:
    $key_3aa4 = { 69 cb [2] 4d c5 [2] 66 e9 [2] 48 cb [2] 5c d0 [2] 53 ca [2] 4d d7 [2] 4f d6 [2] 54 d0 [2] 48 d7 [2] 54 f8 }

  condition:
    any of them
}