rule TTP_XOR_QUAD_CurrentVersionRun_7fb8 {
  strings:
    $key_7fb8 = { 2c d7 [2] 08 d9 [2] 23 f5 [2] 0d d7 [2] 19 cc [2] 16 d6 [2] 08 cb [2] 0a ca [2] 11 cc [2] 0d cb [2] 11 e4 }

  condition:
    any of them
}