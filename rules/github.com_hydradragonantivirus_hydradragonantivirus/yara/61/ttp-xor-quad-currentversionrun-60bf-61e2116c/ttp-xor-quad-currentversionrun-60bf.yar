rule TTP_XOR_QUAD_CurrentVersionRun_60bf {
  strings:
    $key_60bf = { 33 d0 [2] 17 de [2] 3c f2 [2] 12 d0 [2] 06 cb [2] 09 d1 [2] 17 cc [2] 15 cd [2] 0e cb [2] 12 cc [2] 0e e3 }

  condition:
    any of them
}