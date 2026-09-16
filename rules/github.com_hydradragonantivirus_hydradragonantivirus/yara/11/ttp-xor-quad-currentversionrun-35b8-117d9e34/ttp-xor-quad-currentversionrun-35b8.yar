rule TTP_XOR_QUAD_CurrentVersionRun_35b8 {
  strings:
    $key_35b8 = { 66 d7 [2] 42 d9 [2] 69 f5 [2] 47 d7 [2] 53 cc [2] 5c d6 [2] 42 cb [2] 40 ca [2] 5b cc [2] 47 cb [2] 5b e4 }

  condition:
    any of them
}