rule TTP_XOR_QUAD_CurrentVersionRun_63a9 {
  strings:
    $key_63a9 = { 30 c6 [2] 14 c8 [2] 3f e4 [2] 11 c6 [2] 05 dd [2] 0a c7 [2] 14 da [2] 16 db [2] 0d dd [2] 11 da [2] 0d f5 }

  condition:
    any of them
}