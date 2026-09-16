rule TTP_XOR_MULT_DOSStub_1384 {
  strings:
    $key_1384 = { 47 ec [2] 33 f4 [2] 74 f6 [2] 33 e7 [2] 7d eb [2] 71 e1 [2] 66 ea [2] 7d a4 [2] 40 }

  condition:
    any of them
}