rule TTP_XOR_QUAD_CurrentVersionRun_6fbf {
  strings:
    $key_6fbf = { 3c d0 [2] 18 de [2] 33 f2 [2] 1d d0 [2] 09 cb [2] 06 d1 [2] 18 cc [2] 1a cd [2] 01 cb [2] 1d cc [2] 01 e3 }

  condition:
    any of them
}