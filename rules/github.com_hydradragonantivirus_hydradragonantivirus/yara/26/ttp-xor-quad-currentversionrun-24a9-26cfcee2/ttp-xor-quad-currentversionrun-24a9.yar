rule TTP_XOR_QUAD_CurrentVersionRun_24a9 {
  strings:
    $key_24a9 = { 77 c6 [2] 53 c8 [2] 78 e4 [2] 56 c6 [2] 42 dd [2] 4d c7 [2] 53 da [2] 51 db [2] 4a dd [2] 56 da [2] 4a f5 }

  condition:
    any of them
}