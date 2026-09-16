rule TTP_XOR_QUAD_CurrentVersionRun_36b8 {
  strings:
    $key_36b8 = { 65 d7 [2] 41 d9 [2] 6a f5 [2] 44 d7 [2] 50 cc [2] 5f d6 [2] 41 cb [2] 43 ca [2] 58 cc [2] 44 cb [2] 58 e4 }

  condition:
    any of them
}