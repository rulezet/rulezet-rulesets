rule TTP_XOR_QUAD_CurrentVersionRun_5bad {
  strings:
    $key_5bad = { 08 c2 [2] 2c cc [2] 07 e0 [2] 29 c2 [2] 3d d9 [2] 32 c3 [2] 2c de [2] 2e df [2] 35 d9 [2] 29 de [2] 35 f1 }

  condition:
    any of them
}