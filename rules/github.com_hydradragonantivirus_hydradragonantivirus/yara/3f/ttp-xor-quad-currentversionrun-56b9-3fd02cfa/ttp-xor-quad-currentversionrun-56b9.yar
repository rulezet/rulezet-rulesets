rule TTP_XOR_QUAD_CurrentVersionRun_56b9 {
  strings:
    $key_56b9 = { 05 d6 [2] 21 d8 [2] 0a f4 [2] 24 d6 [2] 30 cd [2] 3f d7 [2] 21 ca [2] 23 cb [2] 38 cd [2] 24 ca [2] 38 e5 }

  condition:
    any of them
}