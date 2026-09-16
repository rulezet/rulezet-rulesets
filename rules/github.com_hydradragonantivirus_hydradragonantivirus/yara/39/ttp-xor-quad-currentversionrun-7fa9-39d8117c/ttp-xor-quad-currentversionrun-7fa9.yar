rule TTP_XOR_QUAD_CurrentVersionRun_7fa9 {
  strings:
    $key_7fa9 = { 2c c6 [2] 08 c8 [2] 23 e4 [2] 0d c6 [2] 19 dd [2] 16 c7 [2] 08 da [2] 0a db [2] 11 dd [2] 0d da [2] 11 f5 }

  condition:
    any of them
}