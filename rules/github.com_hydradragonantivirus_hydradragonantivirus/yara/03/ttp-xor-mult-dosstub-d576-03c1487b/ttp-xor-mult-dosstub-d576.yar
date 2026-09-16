rule TTP_XOR_MULT_DOSStub_d576 {
  strings:
    $key_d576 = { 81 1e [2] f5 06 [2] b2 04 [2] f5 15 [2] bb 19 [2] b7 13 [2] a0 18 [2] bb 56 [2] 86 }

  condition:
    any of them
}