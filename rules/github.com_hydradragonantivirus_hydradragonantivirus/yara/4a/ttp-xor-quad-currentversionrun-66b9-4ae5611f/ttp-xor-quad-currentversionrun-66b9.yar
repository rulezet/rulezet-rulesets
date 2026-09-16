rule TTP_XOR_QUAD_CurrentVersionRun_66b9 {
  strings:
    $key_66b9 = { 35 d6 [2] 11 d8 [2] 3a f4 [2] 14 d6 [2] 00 cd [2] 0f d7 [2] 11 ca [2] 13 cb [2] 08 cd [2] 14 ca [2] 08 e5 }

  condition:
    any of them
}