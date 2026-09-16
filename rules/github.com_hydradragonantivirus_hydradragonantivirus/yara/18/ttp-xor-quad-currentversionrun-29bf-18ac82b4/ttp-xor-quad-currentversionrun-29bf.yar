rule TTP_XOR_QUAD_CurrentVersionRun_29bf {
  strings:
    $key_29bf = { 7a d0 [2] 5e de [2] 75 f2 [2] 5b d0 [2] 4f cb [2] 40 d1 [2] 5e cc [2] 5c cd [2] 47 cb [2] 5b cc [2] 47 e3 }

  condition:
    any of them
}