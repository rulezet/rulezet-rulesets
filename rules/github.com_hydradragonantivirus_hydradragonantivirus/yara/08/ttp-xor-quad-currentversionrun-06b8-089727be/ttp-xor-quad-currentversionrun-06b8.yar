rule TTP_XOR_QUAD_CurrentVersionRun_06b8 {
  strings:
    $key_06b8 = { 55 d7 [2] 71 d9 [2] 5a f5 [2] 74 d7 [2] 60 cc [2] 6f d6 [2] 71 cb [2] 73 ca [2] 68 cc [2] 74 cb [2] 68 e4 }

  condition:
    any of them
}