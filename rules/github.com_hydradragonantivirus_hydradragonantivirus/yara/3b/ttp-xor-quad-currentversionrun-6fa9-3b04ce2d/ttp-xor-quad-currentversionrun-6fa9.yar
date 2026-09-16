rule TTP_XOR_QUAD_CurrentVersionRun_6fa9 {
  strings:
    $key_6fa9 = { 3c c6 [2] 18 c8 [2] 33 e4 [2] 1d c6 [2] 09 dd [2] 06 c7 [2] 18 da [2] 1a db [2] 01 dd [2] 1d da [2] 01 f5 }

  condition:
    any of them
}