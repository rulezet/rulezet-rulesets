rule TTP_XOR_QUAD_CurrentVersionRun_4ebf {
  strings:
    $key_4ebf = { 1d d0 [2] 39 de [2] 12 f2 [2] 3c d0 [2] 28 cb [2] 27 d1 [2] 39 cc [2] 3b cd [2] 20 cb [2] 3c cc [2] 20 e3 }

  condition:
    any of them
}