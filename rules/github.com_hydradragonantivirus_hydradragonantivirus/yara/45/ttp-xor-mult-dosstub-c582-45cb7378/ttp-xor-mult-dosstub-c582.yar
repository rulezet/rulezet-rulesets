rule TTP_XOR_MULT_DOSStub_c582 {
  strings:
    $key_c582 = { 91 ea [2] e5 f2 [2] a2 f0 [2] e5 e1 [2] ab ed [2] a7 e7 [2] b0 ec [2] ab a2 [2] 96 }

  condition:
    any of them
}