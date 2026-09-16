rule TTP_XOR_QUAD_CurrentVersionRun_27bf {
  strings:
    $key_27bf = { 74 d0 [2] 50 de [2] 7b f2 [2] 55 d0 [2] 41 cb [2] 4e d1 [2] 50 cc [2] 52 cd [2] 49 cb [2] 55 cc [2] 49 e3 }

  condition:
    any of them
}