rule TTP_XOR_QUAD_CurrentVersionRun_4cbf {
  strings:
    $key_4cbf = { 1f d0 [2] 3b de [2] 10 f2 [2] 3e d0 [2] 2a cb [2] 25 d1 [2] 3b cc [2] 39 cd [2] 22 cb [2] 3e cc [2] 22 e3 }

  condition:
    any of them
}