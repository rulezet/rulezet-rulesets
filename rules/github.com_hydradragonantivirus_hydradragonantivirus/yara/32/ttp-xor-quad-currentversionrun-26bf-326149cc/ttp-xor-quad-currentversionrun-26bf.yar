rule TTP_XOR_QUAD_CurrentVersionRun_26bf {
  strings:
    $key_26bf = { 75 d0 [2] 51 de [2] 7a f2 [2] 54 d0 [2] 40 cb [2] 4f d1 [2] 51 cc [2] 53 cd [2] 48 cb [2] 54 cc [2] 48 e3 }

  condition:
    any of them
}