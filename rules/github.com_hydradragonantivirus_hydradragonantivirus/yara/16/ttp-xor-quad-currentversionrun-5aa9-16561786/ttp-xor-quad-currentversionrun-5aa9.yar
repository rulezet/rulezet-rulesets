rule TTP_XOR_QUAD_CurrentVersionRun_5aa9 {
  strings:
    $key_5aa9 = { 09 c6 [2] 2d c8 [2] 06 e4 [2] 28 c6 [2] 3c dd [2] 33 c7 [2] 2d da [2] 2f db [2] 34 dd [2] 28 da [2] 34 f5 }

  condition:
    any of them
}