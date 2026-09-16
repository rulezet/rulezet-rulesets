rule TTP_XOR_QUAD_CurrentVersionRun_dab4 {
  strings:
    $key_dab4 = { 89 db [2] ad d5 [2] 86 f9 [2] a8 db [2] bc c0 [2] b3 da [2] ad c7 [2] af c6 [2] b4 c0 [2] a8 c7 [2] b4 e8 }

  condition:
    any of them
}