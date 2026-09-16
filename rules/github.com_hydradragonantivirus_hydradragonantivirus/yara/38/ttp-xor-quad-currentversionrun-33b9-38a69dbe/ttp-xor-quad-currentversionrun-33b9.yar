rule TTP_XOR_QUAD_CurrentVersionRun_33b9 {
  strings:
    $key_33b9 = { 60 d6 [2] 44 d8 [2] 6f f4 [2] 41 d6 [2] 55 cd [2] 5a d7 [2] 44 ca [2] 46 cb [2] 5d cd [2] 41 ca [2] 5d e5 }

  condition:
    any of them
}