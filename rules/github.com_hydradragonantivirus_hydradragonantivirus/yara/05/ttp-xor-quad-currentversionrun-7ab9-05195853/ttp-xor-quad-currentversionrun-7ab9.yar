rule TTP_XOR_QUAD_CurrentVersionRun_7ab9 {
  strings:
    $key_7ab9 = { 29 d6 [2] 0d d8 [2] 26 f4 [2] 08 d6 [2] 1c cd [2] 13 d7 [2] 0d ca [2] 0f cb [2] 14 cd [2] 08 ca [2] 14 e5 }

  condition:
    any of them
}