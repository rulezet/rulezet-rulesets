rule TTP_XOR_MULT_DOSStub_d55a {
  strings:
    $key_d55a = { 81 32 [2] f5 2a [2] b2 28 [2] f5 39 [2] bb 35 [2] b7 3f [2] a0 34 [2] bb 7a [2] 86 }

  condition:
    any of them
}