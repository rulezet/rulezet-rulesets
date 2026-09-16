rule TTP_XOR_QUAD_CurrentVersionRun_34a5 {
  strings:
    $key_34a5 = { 67 ca [2] 43 c4 [2] 68 e8 [2] 46 ca [2] 52 d1 [2] 5d cb [2] 43 d6 [2] 41 d7 [2] 5a d1 [2] 46 d6 [2] 5a f9 }

  condition:
    any of them
}