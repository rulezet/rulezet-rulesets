rule TTP_XOR_MULT_DOSStub_5484 {
  strings:
    $key_5484 = { 00 ec [2] 74 f4 [2] 33 f6 [2] 74 e7 [2] 3a eb [2] 36 e1 [2] 21 ea [2] 3a a4 [2] 07 }

  condition:
    any of them
}