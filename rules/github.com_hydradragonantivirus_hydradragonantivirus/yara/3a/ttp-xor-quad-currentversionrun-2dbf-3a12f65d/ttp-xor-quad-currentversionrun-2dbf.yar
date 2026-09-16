rule TTP_XOR_QUAD_CurrentVersionRun_2dbf {
  strings:
    $key_2dbf = { 7e d0 [2] 5a de [2] 71 f2 [2] 5f d0 [2] 4b cb [2] 44 d1 [2] 5a cc [2] 58 cd [2] 43 cb [2] 5f cc [2] 43 e3 }

  condition:
    any of them
}