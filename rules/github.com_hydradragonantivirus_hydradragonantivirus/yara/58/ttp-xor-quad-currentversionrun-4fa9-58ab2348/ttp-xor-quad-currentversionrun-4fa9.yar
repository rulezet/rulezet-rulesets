rule TTP_XOR_QUAD_CurrentVersionRun_4fa9 {
  strings:
    $key_4fa9 = { 1c c6 [2] 38 c8 [2] 13 e4 [2] 3d c6 [2] 29 dd [2] 26 c7 [2] 38 da [2] 3a db [2] 21 dd [2] 3d da [2] 21 f5 }

  condition:
    any of them
}