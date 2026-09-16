rule TTP_XOR_QUAD_CurrentVersionRun_5cbf {
  strings:
    $key_5cbf = { 0f d0 [2] 2b de [2] 00 f2 [2] 2e d0 [2] 3a cb [2] 35 d1 [2] 2b cc [2] 29 cd [2] 32 cb [2] 2e cc [2] 32 e3 }

  condition:
    any of them
}