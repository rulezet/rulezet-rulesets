rule TTP_XOR_MULT_DOSStub_4484 {
  strings:
    $key_4484 = { 10 ec [2] 64 f4 [2] 23 f6 [2] 64 e7 [2] 2a eb [2] 26 e1 [2] 31 ea [2] 2a a4 [2] 17 }

  condition:
    any of them
}