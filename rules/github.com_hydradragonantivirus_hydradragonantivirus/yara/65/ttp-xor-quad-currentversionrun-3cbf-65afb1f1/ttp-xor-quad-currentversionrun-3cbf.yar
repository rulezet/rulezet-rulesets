rule TTP_XOR_QUAD_CurrentVersionRun_3cbf {
  strings:
    $key_3cbf = { 6f d0 [2] 4b de [2] 60 f2 [2] 4e d0 [2] 5a cb [2] 55 d1 [2] 4b cc [2] 49 cd [2] 52 cb [2] 4e cc [2] 52 e3 }

  condition:
    any of them
}