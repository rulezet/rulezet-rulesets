rule TTP_XOR_QUAD_CurrentVersionRun_c9b5 {
  strings:
    $key_c9b5 = { 9a da [2] be d4 [2] 95 f8 [2] bb da [2] af c1 [2] a0 db [2] be c6 [2] bc c7 [2] a7 c1 [2] bb c6 [2] a7 e9 }

  condition:
    any of them
}