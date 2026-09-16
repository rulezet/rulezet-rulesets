rule TTP_XOR_QUAD_CurrentVersionRun_fab8 {
  strings:
    $key_fab8 = { a9 d7 [2] 8d d9 [2] a6 f5 [2] 88 d7 [2] 9c cc [2] 93 d6 [2] 8d cb [2] 8f ca [2] 94 cc [2] 88 cb [2] 94 e4 }

  condition:
    any of them
}