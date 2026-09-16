rule TTP_XOR_QUAD_CurrentVersionRun_79bf {
  strings:
    $key_79bf = { 2a d0 [2] 0e de [2] 25 f2 [2] 0b d0 [2] 1f cb [2] 10 d1 [2] 0e cc [2] 0c cd [2] 17 cb [2] 0b cc [2] 17 e3 }

  condition:
    any of them
}