rule TTP_XOR_QUAD_CurrentVersionRun_74a9 {
  strings:
    $key_74a9 = { 27 c6 [2] 03 c8 [2] 28 e4 [2] 06 c6 [2] 12 dd [2] 1d c7 [2] 03 da [2] 01 db [2] 1a dd [2] 06 da [2] 1a f5 }

  condition:
    any of them
}