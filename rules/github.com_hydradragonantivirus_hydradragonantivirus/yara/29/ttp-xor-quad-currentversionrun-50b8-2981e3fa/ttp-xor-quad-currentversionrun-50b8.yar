rule TTP_XOR_QUAD_CurrentVersionRun_50b8 {
  strings:
    $key_50b8 = { 03 d7 [2] 27 d9 [2] 0c f5 [2] 22 d7 [2] 36 cc [2] 39 d6 [2] 27 cb [2] 25 ca [2] 3e cc [2] 22 cb [2] 3e e4 }

  condition:
    any of them
}