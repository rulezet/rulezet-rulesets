rule TTP_XOR_QUAD_CurrentVersionRun_1eb8 {
  strings:
    $key_1eb8 = { 4d d7 [2] 69 d9 [2] 42 f5 [2] 6c d7 [2] 78 cc [2] 77 d6 [2] 69 cb [2] 6b ca [2] 70 cc [2] 6c cb [2] 70 e4 }

  condition:
    any of them
}