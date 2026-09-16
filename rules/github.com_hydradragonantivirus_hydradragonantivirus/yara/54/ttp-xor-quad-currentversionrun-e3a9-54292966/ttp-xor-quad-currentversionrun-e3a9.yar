rule TTP_XOR_QUAD_CurrentVersionRun_e3a9 {
  strings:
    $key_e3a9 = { b0 c6 [2] 94 c8 [2] bf e4 [2] 91 c6 [2] 85 dd [2] 8a c7 [2] 94 da [2] 96 db [2] 8d dd [2] 91 da [2] 8d f5 }

  condition:
    any of them
}