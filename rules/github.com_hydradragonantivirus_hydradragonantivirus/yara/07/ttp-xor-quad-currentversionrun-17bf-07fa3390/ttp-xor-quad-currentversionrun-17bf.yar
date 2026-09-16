rule TTP_XOR_QUAD_CurrentVersionRun_17bf {
  strings:
    $key_17bf = { 44 d0 [2] 60 de [2] 4b f2 [2] 65 d0 [2] 71 cb [2] 7e d1 [2] 60 cc [2] 62 cd [2] 79 cb [2] 65 cc [2] 79 e3 }

  condition:
    any of them
}