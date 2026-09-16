rule TTP_XOR_QUAD_CurrentVersionRun_f3a9 {
  strings:
    $key_f3a9 = { a0 c6 [2] 84 c8 [2] af e4 [2] 81 c6 [2] 95 dd [2] 9a c7 [2] 84 da [2] 86 db [2] 9d dd [2] 81 da [2] 9d f5 }

  condition:
    any of them
}