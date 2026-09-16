rule TTP_XOR_MULT_DOSStub_2484 {
  strings:
    $key_2484 = { 70 ec [2] 04 f4 [2] 43 f6 [2] 04 e7 [2] 4a eb [2] 46 e1 [2] 51 ea [2] 4a a4 [2] 77 }

  condition:
    any of them
}