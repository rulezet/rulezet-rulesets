rule TTP_XOR_QUAD_CurrentVersionRun_23b9 {
  strings:
    $key_23b9 = { 70 d6 [2] 54 d8 [2] 7f f4 [2] 51 d6 [2] 45 cd [2] 4a d7 [2] 54 ca [2] 56 cb [2] 4d cd [2] 51 ca [2] 4d e5 }

  condition:
    any of them
}