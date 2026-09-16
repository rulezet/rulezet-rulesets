rule TTP_XOR_QUAD_CurrentVersionRun_67bf {
  strings:
    $key_67bf = { 34 d0 [2] 10 de [2] 3b f2 [2] 15 d0 [2] 01 cb [2] 0e d1 [2] 10 cc [2] 12 cd [2] 09 cb [2] 15 cc [2] 09 e3 }

  condition:
    any of them
}