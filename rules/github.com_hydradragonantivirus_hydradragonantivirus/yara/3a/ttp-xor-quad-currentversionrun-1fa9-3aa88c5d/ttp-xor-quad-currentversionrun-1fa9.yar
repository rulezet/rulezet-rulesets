rule TTP_XOR_QUAD_CurrentVersionRun_1fa9 {
  strings:
    $key_1fa9 = { 4c c6 [2] 68 c8 [2] 43 e4 [2] 6d c6 [2] 79 dd [2] 76 c7 [2] 68 da [2] 6a db [2] 71 dd [2] 6d da [2] 71 f5 }

  condition:
    any of them
}