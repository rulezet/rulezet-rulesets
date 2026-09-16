rule TTP_XOR_QUAD_CurrentVersionRun_1cbf {
  strings:
    $key_1cbf = { 4f d0 [2] 6b de [2] 40 f2 [2] 6e d0 [2] 7a cb [2] 75 d1 [2] 6b cc [2] 69 cd [2] 72 cb [2] 6e cc [2] 72 e3 }

  condition:
    any of them
}