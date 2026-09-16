rule TTP_XOR_QUAD_CurrentVersionRun_34a9 {
  strings:
    $key_34a9 = { 67 c6 [2] 43 c8 [2] 68 e4 [2] 46 c6 [2] 52 dd [2] 5d c7 [2] 43 da [2] 41 db [2] 5a dd [2] 46 da [2] 5a f5 }

  condition:
    any of them
}