rule TTP_XOR_QUAD_CurrentVersionRun_07bf {
  strings:
    $key_07bf = { 54 d0 [2] 70 de [2] 5b f2 [2] 75 d0 [2] 61 cb [2] 6e d1 [2] 70 cc [2] 72 cd [2] 69 cb [2] 75 cc [2] 69 e3 }

  condition:
    any of them
}