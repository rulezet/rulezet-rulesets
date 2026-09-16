rule TTP_XOR_QUAD_CurrentVersionRun_72a9 {
  strings:
    $key_72a9 = { 21 c6 [2] 05 c8 [2] 2e e4 [2] 00 c6 [2] 14 dd [2] 1b c7 [2] 05 da [2] 07 db [2] 1c dd [2] 00 da [2] 1c f5 }

  condition:
    any of them
}