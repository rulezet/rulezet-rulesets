rule TTP_XOR_QUAD_CurrentVersionRun_66b8 {
  strings:
    $key_66b8 = { 35 d7 [2] 11 d9 [2] 3a f5 [2] 14 d7 [2] 00 cc [2] 0f d6 [2] 11 cb [2] 13 ca [2] 08 cc [2] 14 cb [2] 08 e4 }

  condition:
    any of them
}