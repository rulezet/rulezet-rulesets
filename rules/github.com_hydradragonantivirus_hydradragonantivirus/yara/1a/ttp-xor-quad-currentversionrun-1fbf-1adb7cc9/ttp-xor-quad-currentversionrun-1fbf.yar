rule TTP_XOR_QUAD_CurrentVersionRun_1fbf {
  strings:
    $key_1fbf = { 4c d0 [2] 68 de [2] 43 f2 [2] 6d d0 [2] 79 cb [2] 76 d1 [2] 68 cc [2] 6a cd [2] 71 cb [2] 6d cc [2] 71 e3 }

  condition:
    any of them
}