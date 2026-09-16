rule TTP_XOR_QUAD_CurrentVersionRun_fab9 {
  strings:
    $key_fab9 = { a9 d6 [2] 8d d8 [2] a6 f4 [2] 88 d6 [2] 9c cd [2] 93 d7 [2] 8d ca [2] 8f cb [2] 94 cd [2] 88 ca [2] 94 e5 }

  condition:
    any of them
}