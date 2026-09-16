rule TTP_XOR_QUAD_CurrentVersionRun_2bb8 {
  strings:
    $key_2bb8 = { 78 d7 [2] 5c d9 [2] 77 f5 [2] 59 d7 [2] 4d cc [2] 42 d6 [2] 5c cb [2] 5e ca [2] 45 cc [2] 59 cb [2] 45 e4 }

  condition:
    any of them
}