rule TTP_XOR_QUAD_CurrentVersionRun_24a5 {
  strings:
    $key_24a5 = { 77 ca [2] 53 c4 [2] 78 e8 [2] 56 ca [2] 42 d1 [2] 4d cb [2] 53 d6 [2] 51 d7 [2] 4a d1 [2] 56 d6 [2] 4a f9 }

  condition:
    any of them
}