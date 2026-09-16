rule TTP_XOR_QUAD_CurrentVersionRun_3abf {
  strings:
    $key_3abf = { 69 d0 [2] 4d de [2] 66 f2 [2] 48 d0 [2] 5c cb [2] 53 d1 [2] 4d cc [2] 4f cd [2] 54 cb [2] 48 cc [2] 54 e3 }

  condition:
    any of them
}