rule TTP_XOR_QUAD_CurrentVersionRun_5bb8 {
  strings:
    $key_5bb8 = { 08 d7 [2] 2c d9 [2] 07 f5 [2] 29 d7 [2] 3d cc [2] 32 d6 [2] 2c cb [2] 2e ca [2] 35 cc [2] 29 cb [2] 35 e4 }

  condition:
    any of them
}