rule TTP_XOR_QUAD_CurrentVersionRun_13bf {
  strings:
    $key_13bf = { 40 d0 [2] 64 de [2] 4f f2 [2] 61 d0 [2] 75 cb [2] 7a d1 [2] 64 cc [2] 66 cd [2] 7d cb [2] 61 cc [2] 7d e3 }

  condition:
    any of them
}