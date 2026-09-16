rule TTP_XOR_QUAD_CurrentVersionRun_4abf {
  strings:
    $key_4abf = { 19 d0 [2] 3d de [2] 16 f2 [2] 38 d0 [2] 2c cb [2] 23 d1 [2] 3d cc [2] 3f cd [2] 24 cb [2] 38 cc [2] 24 e3 }

  condition:
    any of them
}