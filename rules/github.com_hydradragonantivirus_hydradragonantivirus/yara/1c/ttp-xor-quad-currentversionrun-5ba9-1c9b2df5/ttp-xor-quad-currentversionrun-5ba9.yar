rule TTP_XOR_QUAD_CurrentVersionRun_5ba9 {
  strings:
    $key_5ba9 = { 08 c6 [2] 2c c8 [2] 07 e4 [2] 29 c6 [2] 3d dd [2] 32 c7 [2] 2c da [2] 2e db [2] 35 dd [2] 29 da [2] 35 f5 }

  condition:
    any of them
}