rule TTP_XOR_QUAD_CurrentVersionRun_2cb8 {
  strings:
    $key_2cb8 = { 7f d7 [2] 5b d9 [2] 70 f5 [2] 5e d7 [2] 4a cc [2] 45 d6 [2] 5b cb [2] 59 ca [2] 42 cc [2] 5e cb [2] 42 e4 }

  condition:
    any of them
}