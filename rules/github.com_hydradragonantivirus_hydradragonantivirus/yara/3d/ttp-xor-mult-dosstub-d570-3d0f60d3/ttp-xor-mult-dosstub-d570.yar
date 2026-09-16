rule TTP_XOR_MULT_DOSStub_d570 {
  strings:
    $key_d570 = { 81 18 [2] f5 00 [2] b2 02 [2] f5 13 [2] bb 1f [2] b7 15 [2] a0 1e [2] bb 50 [2] 86 }

  condition:
    any of them
}