rule TTP_XOR_MULT_DOSStub_c289 {
  strings:
    $key_c289 = { 96 e1 [2] e2 f9 [2] a5 fb [2] e2 ea [2] ac e6 [2] a0 ec [2] b7 e7 [2] ac a9 [2] 91 }

  condition:
    any of them
}