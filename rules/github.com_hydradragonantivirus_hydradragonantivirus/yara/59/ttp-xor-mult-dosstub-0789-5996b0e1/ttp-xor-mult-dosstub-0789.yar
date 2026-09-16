rule TTP_XOR_MULT_DOSStub_0789 {
  strings:
    $key_0789 = { 53 e1 [2] 27 f9 [2] 60 fb [2] 27 ea [2] 69 e6 [2] 65 ec [2] 72 e7 [2] 69 a9 [2] 54 }

  condition:
    any of them
}