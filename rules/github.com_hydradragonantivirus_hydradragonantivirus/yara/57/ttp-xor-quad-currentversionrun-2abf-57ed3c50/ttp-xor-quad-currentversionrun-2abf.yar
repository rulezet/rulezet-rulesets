rule TTP_XOR_QUAD_CurrentVersionRun_2abf {
  strings:
    $key_2abf = { 79 d0 [2] 5d de [2] 76 f2 [2] 58 d0 [2] 4c cb [2] 43 d1 [2] 5d cc [2] 5f cd [2] 44 cb [2] 58 cc [2] 44 e3 }

  condition:
    any of them
}