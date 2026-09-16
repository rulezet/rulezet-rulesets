rule TTP_XOR_QUAD_CurrentVersionRun_0aa4 {
  strings:
    $key_0aa4 = { 59 cb [2] 7d c5 [2] 56 e9 [2] 78 cb [2] 6c d0 [2] 63 ca [2] 7d d7 [2] 7f d6 [2] 64 d0 [2] 78 d7 [2] 64 f8 }

  condition:
    any of them
}