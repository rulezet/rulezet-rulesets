rule TTP_XOR_QUAD_CurrentVersionRun_56bf {
  strings:
    $key_56bf = { 05 d0 [2] 21 de [2] 0a f2 [2] 24 d0 [2] 30 cb [2] 3f d1 [2] 21 cc [2] 23 cd [2] 38 cb [2] 24 cc [2] 38 e3 }

  condition:
    any of them
}