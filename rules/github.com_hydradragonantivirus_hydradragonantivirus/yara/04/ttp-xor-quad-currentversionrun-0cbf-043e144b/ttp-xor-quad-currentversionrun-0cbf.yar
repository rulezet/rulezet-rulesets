rule TTP_XOR_QUAD_CurrentVersionRun_0cbf {
  strings:
    $key_0cbf = { 5f d0 [2] 7b de [2] 50 f2 [2] 7e d0 [2] 6a cb [2] 65 d1 [2] 7b cc [2] 79 cd [2] 62 cb [2] 7e cc [2] 62 e3 }

  condition:
    any of them
}