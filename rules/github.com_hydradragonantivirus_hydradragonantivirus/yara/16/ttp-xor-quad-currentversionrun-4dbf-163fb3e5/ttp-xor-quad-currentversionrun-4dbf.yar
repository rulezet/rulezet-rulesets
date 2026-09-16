rule TTP_XOR_QUAD_CurrentVersionRun_4dbf {
  strings:
    $key_4dbf = { 1e d0 [2] 3a de [2] 11 f2 [2] 3f d0 [2] 2b cb [2] 24 d1 [2] 3a cc [2] 38 cd [2] 23 cb [2] 3f cc [2] 23 e3 }

  condition:
    any of them
}