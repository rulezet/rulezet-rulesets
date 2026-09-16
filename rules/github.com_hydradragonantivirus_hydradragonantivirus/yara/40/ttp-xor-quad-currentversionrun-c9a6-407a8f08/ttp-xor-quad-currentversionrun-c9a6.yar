rule TTP_XOR_QUAD_CurrentVersionRun_c9a6 {
  strings:
    $key_c9a6 = { 9a c9 [2] be c7 [2] 95 eb [2] bb c9 [2] af d2 [2] a0 c8 [2] be d5 [2] bc d4 [2] a7 d2 [2] bb d5 [2] a7 fa }

  condition:
    any of them
}