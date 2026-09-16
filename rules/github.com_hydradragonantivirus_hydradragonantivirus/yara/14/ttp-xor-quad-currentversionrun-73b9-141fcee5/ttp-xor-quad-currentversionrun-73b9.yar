rule TTP_XOR_QUAD_CurrentVersionRun_73b9 {
  strings:
    $key_73b9 = { 20 d6 [2] 04 d8 [2] 2f f4 [2] 01 d6 [2] 15 cd [2] 1a d7 [2] 04 ca [2] 06 cb [2] 1d cd [2] 01 ca [2] 1d e5 }

  condition:
    any of them
}