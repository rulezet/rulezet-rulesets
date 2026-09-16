rule TTP_XOR_QUAD_CurrentVersionRun_5fbf {
  strings:
    $key_5fbf = { 0c d0 [2] 28 de [2] 03 f2 [2] 2d d0 [2] 39 cb [2] 36 d1 [2] 28 cc [2] 2a cd [2] 31 cb [2] 2d cc [2] 31 e3 }

  condition:
    any of them
}