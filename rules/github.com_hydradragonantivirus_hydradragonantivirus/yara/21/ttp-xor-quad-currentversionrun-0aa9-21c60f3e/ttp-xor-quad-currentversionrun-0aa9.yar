rule TTP_XOR_QUAD_CurrentVersionRun_0aa9 {
  strings:
    $key_0aa9 = { 59 c6 [2] 7d c8 [2] 56 e4 [2] 78 c6 [2] 6c dd [2] 63 c7 [2] 7d da [2] 7f db [2] 64 dd [2] 78 da [2] 64 f5 }

  condition:
    any of them
}