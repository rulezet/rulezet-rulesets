rule TTP_XOR_MULT_DOSStub_84c0 {
  strings:
    $key_84c0 = { d0 a8 [2] a4 b0 [2] e3 b2 [2] a4 a3 [2] ea af [2] e6 a5 [2] f1 ae [2] ea e0 [2] d7 }

  condition:
    any of them
}