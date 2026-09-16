rule TTP_XOR_MULT_DOSStub_1584 {
  strings:
    $key_1584 = { 41 ec [2] 35 f4 [2] 72 f6 [2] 35 e7 [2] 7b eb [2] 77 e1 [2] 60 ea [2] 7b a4 [2] 46 }

  condition:
    any of them
}