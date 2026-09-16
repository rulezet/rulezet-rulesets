rule TTP_XOR_QUAD_CurrentVersionRun_45bf {
  strings:
    $key_45bf = { 16 d0 [2] 32 de [2] 19 f2 [2] 37 d0 [2] 23 cb [2] 2c d1 [2] 32 cc [2] 30 cd [2] 2b cb [2] 37 cc [2] 2b e3 }

  condition:
    any of them
}