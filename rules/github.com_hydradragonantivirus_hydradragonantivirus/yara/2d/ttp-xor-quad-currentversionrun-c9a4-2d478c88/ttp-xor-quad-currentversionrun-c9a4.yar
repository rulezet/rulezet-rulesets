rule TTP_XOR_QUAD_CurrentVersionRun_c9a4 {
  strings:
    $key_c9a4 = { 9a cb [2] be c5 [2] 95 e9 [2] bb cb [2] af d0 [2] a0 ca [2] be d7 [2] bc d6 [2] a7 d0 [2] bb d7 [2] a7 f8 }

  condition:
    any of them
}