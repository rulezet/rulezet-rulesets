rule TTP_XOR_MULT_DOSStub_ca98 {
  strings:
    $key_ca98 = { 9e f0 [2] ea e8 [2] ad ea [2] ea fb [2] a4 f7 [2] a8 fd [2] bf f6 [2] a4 b8 [2] 99 }

  condition:
    any of them
}