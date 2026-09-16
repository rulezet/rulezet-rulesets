rule TTP_XOR_QUAD_CurrentVersionRun_1aa9 {
  strings:
    $key_1aa9 = { 49 c6 [2] 6d c8 [2] 46 e4 [2] 68 c6 [2] 7c dd [2] 73 c7 [2] 6d da [2] 6f db [2] 74 dd [2] 68 da [2] 74 f5 }

  condition:
    any of them
}