rule TTP_XOR_QUAD_CurrentVersionRun_3aa9 {
  strings:
    $key_3aa9 = { 69 c6 [2] 4d c8 [2] 66 e4 [2] 48 c6 [2] 5c dd [2] 53 c7 [2] 4d da [2] 4f db [2] 54 dd [2] 48 da [2] 54 f5 }

  condition:
    any of them
}