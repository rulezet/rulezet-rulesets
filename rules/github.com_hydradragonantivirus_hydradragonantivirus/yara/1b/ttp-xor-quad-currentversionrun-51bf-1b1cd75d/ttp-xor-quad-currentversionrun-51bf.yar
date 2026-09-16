rule TTP_XOR_QUAD_CurrentVersionRun_51bf {
  strings:
    $key_51bf = { 02 d0 [2] 26 de [2] 0d f2 [2] 23 d0 [2] 37 cb [2] 38 d1 [2] 26 cc [2] 24 cd [2] 3f cb [2] 23 cc [2] 3f e3 }

  condition:
    any of them
}