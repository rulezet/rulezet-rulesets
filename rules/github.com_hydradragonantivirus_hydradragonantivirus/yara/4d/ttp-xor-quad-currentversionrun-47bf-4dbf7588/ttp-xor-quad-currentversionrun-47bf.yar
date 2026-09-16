rule TTP_XOR_QUAD_CurrentVersionRun_47bf {
  strings:
    $key_47bf = { 14 d0 [2] 30 de [2] 1b f2 [2] 35 d0 [2] 21 cb [2] 2e d1 [2] 30 cc [2] 32 cd [2] 29 cb [2] 35 cc [2] 29 e3 }

  condition:
    any of them
}