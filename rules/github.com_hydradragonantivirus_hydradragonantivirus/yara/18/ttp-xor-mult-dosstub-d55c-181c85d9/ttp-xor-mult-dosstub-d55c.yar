rule TTP_XOR_MULT_DOSStub_d55c {
  strings:
    $key_d55c = { 81 34 [2] f5 2c [2] b2 2e [2] f5 3f [2] bb 33 [2] b7 39 [2] a0 32 [2] bb 7c [2] 86 }

  condition:
    any of them
}