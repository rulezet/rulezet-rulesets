rule TTP_XOR_QUAD_CurrentVersionRun_64bf {
  strings:
    $key_64bf = { 37 d0 [2] 13 de [2] 38 f2 [2] 16 d0 [2] 02 cb [2] 0d d1 [2] 13 cc [2] 11 cd [2] 0a cb [2] 16 cc [2] 0a e3 }

  condition:
    any of them
}