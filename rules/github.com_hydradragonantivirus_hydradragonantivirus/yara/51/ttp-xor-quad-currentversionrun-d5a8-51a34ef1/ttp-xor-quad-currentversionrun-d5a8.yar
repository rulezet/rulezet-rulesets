rule TTP_XOR_QUAD_CurrentVersionRun_d5a8 {
  strings:
    $key_d5a8 = { 86 c7 [2] a2 c9 [2] 89 e5 [2] a7 c7 [2] b3 dc [2] bc c6 [2] a2 db [2] a0 da [2] bb dc [2] a7 db [2] bb f4 }

  condition:
    any of them
}