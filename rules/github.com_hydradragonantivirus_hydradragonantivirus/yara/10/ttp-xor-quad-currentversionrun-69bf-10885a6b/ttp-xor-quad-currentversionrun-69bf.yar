rule TTP_XOR_QUAD_CurrentVersionRun_69bf {
  strings:
    $key_69bf = { 3a d0 [2] 1e de [2] 35 f2 [2] 1b d0 [2] 0f cb [2] 00 d1 [2] 1e cc [2] 1c cd [2] 07 cb [2] 1b cc [2] 07 e3 }

  condition:
    any of them
}