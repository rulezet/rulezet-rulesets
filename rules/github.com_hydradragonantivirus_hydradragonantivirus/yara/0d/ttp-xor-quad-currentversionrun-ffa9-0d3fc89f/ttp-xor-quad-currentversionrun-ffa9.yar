rule TTP_XOR_QUAD_CurrentVersionRun_ffa9 {
  strings:
    $key_ffa9 = { ac c6 [2] 88 c8 [2] a3 e4 [2] 8d c6 [2] 99 dd [2] 96 c7 [2] 88 da [2] 8a db [2] 91 dd [2] 8d da [2] 91 f5 }

  condition:
    any of them
}