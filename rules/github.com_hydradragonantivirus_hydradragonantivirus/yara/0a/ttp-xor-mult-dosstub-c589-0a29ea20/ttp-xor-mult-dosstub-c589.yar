rule TTP_XOR_MULT_DOSStub_c589 {
  strings:
    $key_c589 = { 91 e1 [2] e5 f9 [2] a2 fb [2] e5 ea [2] ab e6 [2] a7 ec [2] b0 e7 [2] ab a9 [2] 96 }

  condition:
    any of them
}