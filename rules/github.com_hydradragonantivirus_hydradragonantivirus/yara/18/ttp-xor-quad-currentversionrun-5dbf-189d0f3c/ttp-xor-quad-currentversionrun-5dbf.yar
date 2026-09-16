rule TTP_XOR_QUAD_CurrentVersionRun_5dbf {
  strings:
    $key_5dbf = { 0e d0 [2] 2a de [2] 01 f2 [2] 2f d0 [2] 3b cb [2] 34 d1 [2] 2a cc [2] 28 cd [2] 33 cb [2] 2f cc [2] 33 e3 }

  condition:
    any of them
}