rule TTP_XOR_QUAD_CurrentVersionRun_36bf {
  strings:
    $key_36bf = { 65 d0 [2] 41 de [2] 6a f2 [2] 44 d0 [2] 50 cb [2] 5f d1 [2] 41 cc [2] 43 cd [2] 58 cb [2] 44 cc [2] 58 e3 }

  condition:
    any of them
}