rule TTP_XOR_MULT_DOSStub_d572 {
  strings:
    $key_d572 = { 81 1a [2] f5 02 [2] b2 00 [2] f5 11 [2] bb 1d [2] b7 17 [2] a0 1c [2] bb 52 [2] 86 }

  condition:
    any of them
}