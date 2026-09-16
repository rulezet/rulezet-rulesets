rule TTP_XOR_QUAD_CurrentVersionRun_fca9 {
  strings:
    $key_fca9 = { af c6 [2] 8b c8 [2] a0 e4 [2] 8e c6 [2] 9a dd [2] 95 c7 [2] 8b da [2] 89 db [2] 92 dd [2] 8e da [2] 92 f5 }

  condition:
    any of them
}