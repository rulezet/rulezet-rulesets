rule TTP_XOR_QUAD_CurrentVersionRun_35a4 {
  strings:
    $key_35a4 = { 66 cb [2] 42 c5 [2] 69 e9 [2] 47 cb [2] 53 d0 [2] 5c ca [2] 42 d7 [2] 40 d6 [2] 5b d0 [2] 47 d7 [2] 5b f8 }

  condition:
    any of them
}