rule TTP_XOR_QUAD_CurrentVersionRun_42b9 {
  strings:
    $key_42b9 = { 11 d6 [2] 35 d8 [2] 1e f4 [2] 30 d6 [2] 24 cd [2] 2b d7 [2] 35 ca [2] 37 cb [2] 2c cd [2] 30 ca [2] 2c e5 }

  condition:
    any of them
}