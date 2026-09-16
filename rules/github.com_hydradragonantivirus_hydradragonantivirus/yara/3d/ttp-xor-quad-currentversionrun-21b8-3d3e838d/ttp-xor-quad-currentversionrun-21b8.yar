rule TTP_XOR_QUAD_CurrentVersionRun_21b8 {
  strings:
    $key_21b8 = { 72 d7 [2] 56 d9 [2] 7d f5 [2] 53 d7 [2] 47 cc [2] 48 d6 [2] 56 cb [2] 54 ca [2] 4f cc [2] 53 cb [2] 4f e4 }

  condition:
    any of them
}