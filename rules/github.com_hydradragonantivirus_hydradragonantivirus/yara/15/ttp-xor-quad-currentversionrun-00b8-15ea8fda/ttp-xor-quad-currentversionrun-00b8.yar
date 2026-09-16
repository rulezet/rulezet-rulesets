rule TTP_XOR_QUAD_CurrentVersionRun_00b8 {
  strings:
    $key_00b8 = { 53 d7 [2] 77 d9 [2] 5c f5 [2] 72 d7 [2] 66 cc [2] 69 d6 [2] 77 cb [2] 75 ca [2] 6e cc [2] 72 cb [2] 6e e4 }

  condition:
    any of them
}