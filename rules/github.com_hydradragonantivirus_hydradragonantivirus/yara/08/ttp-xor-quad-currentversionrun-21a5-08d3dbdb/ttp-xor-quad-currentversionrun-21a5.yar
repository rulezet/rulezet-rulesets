rule TTP_XOR_QUAD_CurrentVersionRun_21a5 {
  strings:
    $key_21a5 = { 72 ca [2] 56 c4 [2] 7d e8 [2] 53 ca [2] 47 d1 [2] 48 cb [2] 56 d6 [2] 54 d7 [2] 4f d1 [2] 53 d6 [2] 4f f9 }

  condition:
    any of them
}