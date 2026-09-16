rule TTP_XOR_QUAD_CurrentVersionRun_3fa9 {
  strings:
    $key_3fa9 = { 6c c6 [2] 48 c8 [2] 63 e4 [2] 4d c6 [2] 59 dd [2] 56 c7 [2] 48 da [2] 4a db [2] 51 dd [2] 4d da [2] 51 f5 }

  condition:
    any of them
}