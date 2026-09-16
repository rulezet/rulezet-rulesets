rule TTP_XOR_QUAD_CurrentVersionRun_40a9 {
  strings:
    $key_40a9 = { 13 c6 [2] 37 c8 [2] 1c e4 [2] 32 c6 [2] 26 dd [2] 29 c7 [2] 37 da [2] 35 db [2] 2e dd [2] 32 da [2] 2e f5 }

  condition:
    any of them
}