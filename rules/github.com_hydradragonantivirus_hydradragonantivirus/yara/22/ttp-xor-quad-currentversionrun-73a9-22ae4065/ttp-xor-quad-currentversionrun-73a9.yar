rule TTP_XOR_QUAD_CurrentVersionRun_73a9 {
  strings:
    $key_73a9 = { 20 c6 [2] 04 c8 [2] 2f e4 [2] 01 c6 [2] 15 dd [2] 1a c7 [2] 04 da [2] 06 db [2] 1d dd [2] 01 da [2] 1d f5 }

  condition:
    any of them
}