rule TTP_XOR_QUAD_CurrentVersionRun_4ab8 {
  strings:
    $key_4ab8 = { 19 d7 [2] 3d d9 [2] 16 f5 [2] 38 d7 [2] 2c cc [2] 23 d6 [2] 3d cb [2] 3f ca [2] 24 cc [2] 38 cb [2] 24 e4 }

  condition:
    any of them
}