rule TTP_XOR_QUAD_CurrentVersionRun_caa9 {
  strings:
    $key_caa9 = { 99 c6 [2] bd c8 [2] 96 e4 [2] b8 c6 [2] ac dd [2] a3 c7 [2] bd da [2] bf db [2] a4 dd [2] b8 da [2] a4 f5 }

  condition:
    any of them
}