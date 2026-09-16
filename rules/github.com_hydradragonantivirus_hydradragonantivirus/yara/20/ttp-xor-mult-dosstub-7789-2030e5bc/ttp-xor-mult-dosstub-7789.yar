rule TTP_XOR_MULT_DOSStub_7789 {
  strings:
    $key_7789 = { 23 e1 [2] 57 f9 [2] 10 fb [2] 57 ea [2] 19 e6 [2] 15 ec [2] 02 e7 [2] 19 a9 [2] 24 }

  condition:
    any of them
}