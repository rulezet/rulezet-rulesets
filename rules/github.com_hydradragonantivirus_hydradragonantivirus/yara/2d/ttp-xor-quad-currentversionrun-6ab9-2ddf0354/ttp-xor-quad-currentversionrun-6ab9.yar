rule TTP_XOR_QUAD_CurrentVersionRun_6ab9 {
  strings:
    $key_6ab9 = { 39 d6 [2] 1d d8 [2] 36 f4 [2] 18 d6 [2] 0c cd [2] 03 d7 [2] 1d ca [2] 1f cb [2] 04 cd [2] 18 ca [2] 04 e5 }

  condition:
    any of them
}