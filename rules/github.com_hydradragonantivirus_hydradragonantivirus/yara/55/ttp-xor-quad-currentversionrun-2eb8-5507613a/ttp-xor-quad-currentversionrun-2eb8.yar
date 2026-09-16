rule TTP_XOR_QUAD_CurrentVersionRun_2eb8 {
  strings:
    $key_2eb8 = { 7d d7 [2] 59 d9 [2] 72 f5 [2] 5c d7 [2] 48 cc [2] 47 d6 [2] 59 cb [2] 5b ca [2] 40 cc [2] 5c cb [2] 40 e4 }

  condition:
    any of them
}