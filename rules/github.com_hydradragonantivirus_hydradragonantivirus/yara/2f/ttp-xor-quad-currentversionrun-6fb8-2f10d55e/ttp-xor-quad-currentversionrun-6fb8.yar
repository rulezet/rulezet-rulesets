rule TTP_XOR_QUAD_CurrentVersionRun_6fb8 {
  strings:
    $key_6fb8 = { 3c d7 [2] 18 d9 [2] 33 f5 [2] 1d d7 [2] 09 cc [2] 06 d6 [2] 18 cb [2] 1a ca [2] 01 cc [2] 1d cb [2] 01 e4 }

  condition:
    any of them
}