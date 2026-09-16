rule TTP_XOR_MULT_DOSStub_6789 {
  strings:
    $key_6789 = { 33 e1 [2] 47 f9 [2] 00 fb [2] 47 ea [2] 09 e6 [2] 05 ec [2] 12 e7 [2] 09 a9 [2] 34 }

  condition:
    any of them
}