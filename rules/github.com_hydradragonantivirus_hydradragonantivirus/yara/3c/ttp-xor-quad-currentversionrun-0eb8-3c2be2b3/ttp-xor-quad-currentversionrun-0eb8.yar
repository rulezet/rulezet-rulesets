rule TTP_XOR_QUAD_CurrentVersionRun_0eb8 {
  strings:
    $key_0eb8 = { 5d d7 [2] 79 d9 [2] 52 f5 [2] 7c d7 [2] 68 cc [2] 67 d6 [2] 79 cb [2] 7b ca [2] 60 cc [2] 7c cb [2] 60 e4 }

  condition:
    any of them
}