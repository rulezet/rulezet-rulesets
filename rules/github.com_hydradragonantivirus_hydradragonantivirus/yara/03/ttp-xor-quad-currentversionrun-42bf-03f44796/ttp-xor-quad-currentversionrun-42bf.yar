rule TTP_XOR_QUAD_CurrentVersionRun_42bf {
  strings:
    $key_42bf = { 11 d0 [2] 35 de [2] 1e f2 [2] 30 d0 [2] 24 cb [2] 2b d1 [2] 35 cc [2] 37 cd [2] 2c cb [2] 30 cc [2] 2c e3 }

  condition:
    any of them
}