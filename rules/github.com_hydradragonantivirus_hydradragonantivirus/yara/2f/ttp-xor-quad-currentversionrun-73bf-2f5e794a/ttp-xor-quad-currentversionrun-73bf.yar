rule TTP_XOR_QUAD_CurrentVersionRun_73bf {
  strings:
    $key_73bf = { 20 d0 [2] 04 de [2] 2f f2 [2] 01 d0 [2] 15 cb [2] 1a d1 [2] 04 cc [2] 06 cd [2] 1d cb [2] 01 cc [2] 1d e3 }

  condition:
    any of them
}