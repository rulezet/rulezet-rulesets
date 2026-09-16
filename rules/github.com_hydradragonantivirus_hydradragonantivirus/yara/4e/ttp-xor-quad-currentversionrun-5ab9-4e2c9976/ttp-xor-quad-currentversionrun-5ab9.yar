rule TTP_XOR_QUAD_CurrentVersionRun_5ab9 {
  strings:
    $key_5ab9 = { 09 d6 [2] 2d d8 [2] 06 f4 [2] 28 d6 [2] 3c cd [2] 33 d7 [2] 2d ca [2] 2f cb [2] 34 cd [2] 28 ca [2] 34 e5 }

  condition:
    any of them
}