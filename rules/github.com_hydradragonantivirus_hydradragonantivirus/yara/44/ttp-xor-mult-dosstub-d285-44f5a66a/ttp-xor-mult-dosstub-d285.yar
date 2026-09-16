rule TTP_XOR_MULT_DOSStub_d285 {
  strings:
    $key_d285 = { 86 ed [2] f2 f5 [2] b5 f7 [2] f2 e6 [2] bc ea [2] b0 e0 [2] a7 eb [2] bc a5 [2] 81 }

  condition:
    any of them
}