rule TTP_XOR_QUAD_CurrentVersionRun_5b9c {
  strings:
    $key_5b9c = { 08 f3 [2] 2c fd [2] 07 d1 [2] 29 f3 [2] 3d e8 [2] 32 f2 [2] 2c ef [2] 2e ee [2] 35 e8 [2] 29 ef [2] 35 c0 }

  condition:
    any of them
}