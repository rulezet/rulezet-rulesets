rule TTP_XOR_QUAD_CurrentVersionRun_46b9 {
  strings:
    $key_46b9 = { 15 d6 [2] 31 d8 [2] 1a f4 [2] 34 d6 [2] 20 cd [2] 2f d7 [2] 31 ca [2] 33 cb [2] 28 cd [2] 34 ca [2] 28 e5 }

  condition:
    any of them
}