rule TTP_XOR_QUAD_CurrentVersionRun_6aa9 {
  strings:
    $key_6aa9 = { 39 c6 [2] 1d c8 [2] 36 e4 [2] 18 c6 [2] 0c dd [2] 03 c7 [2] 1d da [2] 1f db [2] 04 dd [2] 18 da [2] 04 f5 }

  condition:
    any of them
}