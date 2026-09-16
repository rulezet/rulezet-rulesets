rule TTP_XOR_QUAD_CurrentVersionRun_d5a6 {
  strings:
    $key_d5a6 = { 86 c9 [2] a2 c7 [2] 89 eb [2] a7 c9 [2] b3 d2 [2] bc c8 [2] a2 d5 [2] a0 d4 [2] bb d2 [2] a7 d5 [2] bb fa }

  condition:
    any of them
}