rule TTP_XOR_QUAD_CurrentVersionRun_39bf {
  strings:
    $key_39bf = { 6a d0 [2] 4e de [2] 65 f2 [2] 4b d0 [2] 5f cb [2] 50 d1 [2] 4e cc [2] 4c cd [2] 57 cb [2] 4b cc [2] 57 e3 }

  condition:
    any of them
}