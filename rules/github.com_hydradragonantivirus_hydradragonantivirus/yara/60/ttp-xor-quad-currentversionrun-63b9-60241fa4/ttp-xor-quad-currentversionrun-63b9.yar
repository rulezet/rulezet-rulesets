rule TTP_XOR_QUAD_CurrentVersionRun_63b9 {
  strings:
    $key_63b9 = { 30 d6 [2] 14 d8 [2] 3f f4 [2] 11 d6 [2] 05 cd [2] 0a d7 [2] 14 ca [2] 16 cb [2] 0d cd [2] 11 ca [2] 0d e5 }

  condition:
    any of them
}