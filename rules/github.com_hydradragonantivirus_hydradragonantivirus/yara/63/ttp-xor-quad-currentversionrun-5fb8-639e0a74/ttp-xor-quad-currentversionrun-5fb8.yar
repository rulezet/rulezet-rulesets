rule TTP_XOR_QUAD_CurrentVersionRun_5fb8 {
  strings:
    $key_5fb8 = { 0c d7 [2] 28 d9 [2] 03 f5 [2] 2d d7 [2] 39 cc [2] 36 d6 [2] 28 cb [2] 2a ca [2] 31 cc [2] 2d cb [2] 31 e4 }

  condition:
    any of them
}