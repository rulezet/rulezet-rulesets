rule TTP_XOR_MULT_DOSStub_d540 {
  strings:
    $key_d540 = { 81 28 [2] f5 30 [2] b2 32 [2] f5 23 [2] bb 2f [2] b7 25 [2] a0 2e [2] bb 60 [2] 86 }

  condition:
    any of them
}