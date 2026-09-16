rule TTP_XOR_QUAD_CurrentVersionRun_5ab8 {
  strings:
    $key_5ab8 = { 09 d7 [2] 2d d9 [2] 06 f5 [2] 28 d7 [2] 3c cc [2] 33 d6 [2] 2d cb [2] 2f ca [2] 34 cc [2] 28 cb [2] 34 e4 }

  condition:
    any of them
}