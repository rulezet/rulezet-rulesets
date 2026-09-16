rule TTP_XOR_QUAD_CurrentVersionRun_40b8 {
  strings:
    $key_40b8 = { 13 d7 [2] 37 d9 [2] 1c f5 [2] 32 d7 [2] 26 cc [2] 29 d6 [2] 37 cb [2] 35 ca [2] 2e cc [2] 32 cb [2] 2e e4 }

  condition:
    any of them
}