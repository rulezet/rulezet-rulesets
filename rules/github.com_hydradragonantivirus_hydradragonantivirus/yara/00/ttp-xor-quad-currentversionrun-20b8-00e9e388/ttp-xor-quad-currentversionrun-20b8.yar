rule TTP_XOR_QUAD_CurrentVersionRun_20b8 {
  strings:
    $key_20b8 = { 73 d7 [2] 57 d9 [2] 7c f5 [2] 52 d7 [2] 46 cc [2] 49 d6 [2] 57 cb [2] 55 ca [2] 4e cc [2] 52 cb [2] 4e e4 }

  condition:
    any of them
}