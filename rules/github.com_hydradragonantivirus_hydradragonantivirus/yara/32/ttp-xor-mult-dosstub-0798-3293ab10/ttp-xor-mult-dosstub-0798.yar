rule TTP_XOR_MULT_DOSStub_0798 {
  strings:
    $key_0798 = { 53 f0 [2] 27 e8 [2] 60 ea [2] 27 fb [2] 69 f7 [2] 65 fd [2] 72 f6 [2] 69 b8 [2] 54 }

  condition:
    any of them
}