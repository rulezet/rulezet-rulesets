rule TTP_XOR_QUAD_CurrentVersionRun_5fa9 {
  strings:
    $key_5fa9 = { 0c c6 [2] 28 c8 [2] 03 e4 [2] 2d c6 [2] 39 dd [2] 36 c7 [2] 28 da [2] 2a db [2] 31 dd [2] 2d da [2] 31 f5 }

  condition:
    any of them
}