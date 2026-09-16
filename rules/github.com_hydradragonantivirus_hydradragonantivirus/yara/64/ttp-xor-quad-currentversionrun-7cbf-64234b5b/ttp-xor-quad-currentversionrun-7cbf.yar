rule TTP_XOR_QUAD_CurrentVersionRun_7cbf {
  strings:
    $key_7cbf = { 2f d0 [2] 0b de [2] 20 f2 [2] 0e d0 [2] 1a cb [2] 15 d1 [2] 0b cc [2] 09 cd [2] 12 cb [2] 0e cc [2] 12 e3 }

  condition:
    any of them
}