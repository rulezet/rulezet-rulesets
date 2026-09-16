rule TTP_XOR_QUAD_CurrentVersionRun_62b9 {
  strings:
    $key_62b9 = { 31 d6 [2] 15 d8 [2] 3e f4 [2] 10 d6 [2] 04 cd [2] 0b d7 [2] 15 ca [2] 17 cb [2] 0c cd [2] 10 ca [2] 0c e5 }

  condition:
    any of them
}