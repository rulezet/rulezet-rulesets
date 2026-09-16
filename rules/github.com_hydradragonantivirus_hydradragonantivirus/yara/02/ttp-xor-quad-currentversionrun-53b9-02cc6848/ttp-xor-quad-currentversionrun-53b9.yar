rule TTP_XOR_QUAD_CurrentVersionRun_53b9 {
  strings:
    $key_53b9 = { 00 d6 [2] 24 d8 [2] 0f f4 [2] 21 d6 [2] 35 cd [2] 3a d7 [2] 24 ca [2] 26 cb [2] 3d cd [2] 21 ca [2] 3d e5 }

  condition:
    any of them
}