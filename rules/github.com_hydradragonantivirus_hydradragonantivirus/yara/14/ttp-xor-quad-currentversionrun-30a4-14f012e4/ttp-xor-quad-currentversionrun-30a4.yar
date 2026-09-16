rule TTP_XOR_QUAD_CurrentVersionRun_30a4 {
  strings:
    $key_30a4 = { 63 cb [2] 47 c5 [2] 6c e9 [2] 42 cb [2] 56 d0 [2] 59 ca [2] 47 d7 [2] 45 d6 [2] 5e d0 [2] 42 d7 [2] 5e f8 }

  condition:
    any of them
}