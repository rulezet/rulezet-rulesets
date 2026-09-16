rule TTP_XOR_QUAD_CurrentVersionRun_03b9 {
  strings:
    $key_03b9 = { 50 d6 [2] 74 d8 [2] 5f f4 [2] 71 d6 [2] 65 cd [2] 6a d7 [2] 74 ca [2] 76 cb [2] 6d cd [2] 71 ca [2] 6d e5 }

  condition:
    any of them
}