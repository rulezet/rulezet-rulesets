rule TTP_XOR_QUAD_CurrentVersionRun_44bf {
  strings:
    $key_44bf = { 17 d0 [2] 33 de [2] 18 f2 [2] 36 d0 [2] 22 cb [2] 2d d1 [2] 33 cc [2] 31 cd [2] 2a cb [2] 36 cc [2] 2a e3 }

  condition:
    any of them
}