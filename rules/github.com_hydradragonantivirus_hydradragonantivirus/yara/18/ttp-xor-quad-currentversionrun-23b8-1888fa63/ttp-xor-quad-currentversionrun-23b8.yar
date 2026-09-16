rule TTP_XOR_QUAD_CurrentVersionRun_23b8 {
  strings:
    $key_23b8 = { 70 d7 [2] 54 d9 [2] 7f f5 [2] 51 d7 [2] 45 cc [2] 4a d6 [2] 54 cb [2] 56 ca [2] 4d cc [2] 51 cb [2] 4d e4 }

  condition:
    any of them
}