rule TTP_XOR_QUAD_CurrentVersionRun_31bf {
  strings:
    $key_31bf = { 62 d0 [2] 46 de [2] 6d f2 [2] 43 d0 [2] 57 cb [2] 58 d1 [2] 46 cc [2] 44 cd [2] 5f cb [2] 43 cc [2] 5f e3 }

  condition:
    any of them
}