rule TTP_XOR_MULT_DOSStub_c598 {
  strings:
    $key_c598 = { 91 f0 [2] e5 e8 [2] a2 ea [2] e5 fb [2] ab f7 [2] a7 fd [2] b0 f6 [2] ab b8 [2] 96 }

  condition:
    any of them
}