rule TTP_XOR_QUAD_CurrentVersionRun_66bf {
  strings:
    $key_66bf = { 35 d0 [2] 11 de [2] 3a f2 [2] 14 d0 [2] 00 cb [2] 0f d1 [2] 11 cc [2] 13 cd [2] 08 cb [2] 14 cc [2] 08 e3 }

  condition:
    any of them
}