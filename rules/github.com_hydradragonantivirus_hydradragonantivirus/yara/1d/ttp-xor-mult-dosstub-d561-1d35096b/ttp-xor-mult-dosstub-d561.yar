rule TTP_XOR_MULT_DOSStub_d561 {
  strings:
    $key_d561 = { 81 09 [2] f5 11 [2] b2 13 [2] f5 02 [2] bb 0e [2] b7 04 [2] a0 0f [2] bb 41 [2] 86 }

  condition:
    any of them
}