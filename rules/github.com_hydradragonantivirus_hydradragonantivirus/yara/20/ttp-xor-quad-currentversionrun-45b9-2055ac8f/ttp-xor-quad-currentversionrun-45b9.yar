rule TTP_XOR_QUAD_CurrentVersionRun_45b9 {
  strings:
    $key_45b9 = { 16 d6 [2] 32 d8 [2] 19 f4 [2] 37 d6 [2] 23 cd [2] 2c d7 [2] 32 ca [2] 30 cb [2] 2b cd [2] 37 ca [2] 2b e5 }

  condition:
    any of them
}