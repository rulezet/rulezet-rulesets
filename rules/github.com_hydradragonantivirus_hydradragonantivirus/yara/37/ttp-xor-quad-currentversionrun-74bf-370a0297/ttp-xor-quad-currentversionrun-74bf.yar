rule TTP_XOR_QUAD_CurrentVersionRun_74bf {
  strings:
    $key_74bf = { 27 d0 [2] 03 de [2] 28 f2 [2] 06 d0 [2] 12 cb [2] 1d d1 [2] 03 cc [2] 01 cd [2] 1a cb [2] 06 cc [2] 1a e3 }

  condition:
    any of them
}