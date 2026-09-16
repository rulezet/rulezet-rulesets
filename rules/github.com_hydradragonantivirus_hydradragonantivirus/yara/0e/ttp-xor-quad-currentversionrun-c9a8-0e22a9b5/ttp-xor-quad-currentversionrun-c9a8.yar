rule TTP_XOR_QUAD_CurrentVersionRun_c9a8 {
  strings:
    $key_c9a8 = { 9a c7 [2] be c9 [2] 95 e5 [2] bb c7 [2] af dc [2] a0 c6 [2] be db [2] bc da [2] a7 dc [2] bb db [2] a7 f4 }

  condition:
    any of them
}