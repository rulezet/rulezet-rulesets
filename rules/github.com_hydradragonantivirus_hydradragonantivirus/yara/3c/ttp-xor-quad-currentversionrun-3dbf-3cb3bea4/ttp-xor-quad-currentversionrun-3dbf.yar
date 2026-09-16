rule TTP_XOR_QUAD_CurrentVersionRun_3dbf {
  strings:
    $key_3dbf = { 6e d0 [2] 4a de [2] 61 f2 [2] 4f d0 [2] 5b cb [2] 54 d1 [2] 4a cc [2] 48 cd [2] 53 cb [2] 4f cc [2] 53 e3 }

  condition:
    any of them
}