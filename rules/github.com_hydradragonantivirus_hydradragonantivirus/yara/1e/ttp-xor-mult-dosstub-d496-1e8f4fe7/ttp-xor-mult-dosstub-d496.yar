rule TTP_XOR_MULT_DOSStub_d496 {
  strings:
    $key_d496 = { 80 fe [2] f4 e6 [2] b3 e4 [2] f4 f5 [2] ba f9 [2] b6 f3 [2] a1 f8 [2] ba b6 [2] 87 }

  condition:
    any of them
}