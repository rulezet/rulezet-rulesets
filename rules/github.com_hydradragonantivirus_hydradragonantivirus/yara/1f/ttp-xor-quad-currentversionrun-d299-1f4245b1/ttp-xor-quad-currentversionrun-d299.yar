rule TTP_XOR_QUAD_CurrentVersionRun_d299 {
  strings:
    $key_d299 = { 81 f6 [2] a5 f8 [2] 8e d4 [2] a0 f6 [2] b4 ed [2] bb f7 [2] a5 ea [2] a7 eb [2] bc ed [2] a0 ea [2] bc c5 }

  condition:
    any of them
}