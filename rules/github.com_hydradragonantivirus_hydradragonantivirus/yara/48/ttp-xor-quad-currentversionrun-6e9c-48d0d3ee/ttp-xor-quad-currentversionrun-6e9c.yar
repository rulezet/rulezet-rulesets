rule TTP_XOR_QUAD_CurrentVersionRun_6e9c {
  strings:
    $key_6e9c = { 3d f3 [2] 19 fd [2] 32 d1 [2] 1c f3 [2] 08 e8 [2] 07 f2 [2] 19 ef [2] 1b ee [2] 00 e8 [2] 1c ef [2] 00 c0 }

  condition:
    any of them
}