rule TTP_XOR_QUAD_CurrentVersionRun_12b9 {
  strings:
    $key_12b9 = { 41 d6 [2] 65 d8 [2] 4e f4 [2] 60 d6 [2] 74 cd [2] 7b d7 [2] 65 ca [2] 67 cb [2] 7c cd [2] 60 ca [2] 7c e5 }

  condition:
    any of them
}