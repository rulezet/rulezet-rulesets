rule TTP_XOR_QUAD_CurrentVersionRun_7ebf {
  strings:
    $key_7ebf = { 2d d0 [2] 09 de [2] 22 f2 [2] 0c d0 [2] 18 cb [2] 17 d1 [2] 09 cc [2] 0b cd [2] 10 cb [2] 0c cc [2] 10 e3 }

  condition:
    any of them
}