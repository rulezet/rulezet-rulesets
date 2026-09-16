rule TTP_XOR_QUAD_CurrentVersionRun_51b9 {
  strings:
    $key_51b9 = { 02 d6 [2] 26 d8 [2] 0d f4 [2] 23 d6 [2] 37 cd [2] 38 d7 [2] 26 ca [2] 24 cb [2] 3f cd [2] 23 ca [2] 3f e5 }

  condition:
    any of them
}