rule TTP_XOR_QUAD_CurrentVersionRun_7ab8 {
  strings:
    $key_7ab8 = { 29 d7 [2] 0d d9 [2] 26 f5 [2] 08 d7 [2] 1c cc [2] 13 d6 [2] 0d cb [2] 0f ca [2] 14 cc [2] 08 cb [2] 14 e4 }

  condition:
    any of them
}