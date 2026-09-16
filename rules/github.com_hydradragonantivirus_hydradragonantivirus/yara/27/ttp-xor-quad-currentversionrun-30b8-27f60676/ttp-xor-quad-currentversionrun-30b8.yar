rule TTP_XOR_QUAD_CurrentVersionRun_30b8 {
  strings:
    $key_30b8 = { 63 d7 [2] 47 d9 [2] 6c f5 [2] 42 d7 [2] 56 cc [2] 59 d6 [2] 47 cb [2] 45 ca [2] 5e cc [2] 42 cb [2] 5e e4 }

  condition:
    any of them
}