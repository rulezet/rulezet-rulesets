rule TTP_XOR_QUAD_CurrentVersionRun_d5a9 {
  strings:
    $key_d5a9 = { 86 c6 [2] a2 c8 [2] 89 e4 [2] a7 c6 [2] b3 dd [2] bc c7 [2] a2 da [2] a0 db [2] bb dd [2] a7 da [2] bb f5 }

  condition:
    any of them
}