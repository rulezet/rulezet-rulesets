rule TTP_XOR_QUAD_CurrentVersionRun_dea9 {
  strings:
    $key_dea9 = { 8d c6 [2] a9 c8 [2] 82 e4 [2] ac c6 [2] b8 dd [2] b7 c7 [2] a9 da [2] ab db [2] b0 dd [2] ac da [2] b0 f5 }

  condition:
    any of them
}