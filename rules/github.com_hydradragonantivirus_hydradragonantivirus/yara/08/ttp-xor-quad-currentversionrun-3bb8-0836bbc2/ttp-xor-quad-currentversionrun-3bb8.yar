rule TTP_XOR_QUAD_CurrentVersionRun_3bb8 {
  strings:
    $key_3bb8 = { 68 d7 [2] 4c d9 [2] 67 f5 [2] 49 d7 [2] 5d cc [2] 52 d6 [2] 4c cb [2] 4e ca [2] 55 cc [2] 49 cb [2] 55 e4 }

  condition:
    any of them
}