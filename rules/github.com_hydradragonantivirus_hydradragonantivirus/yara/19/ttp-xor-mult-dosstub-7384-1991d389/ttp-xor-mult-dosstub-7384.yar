rule TTP_XOR_MULT_DOSStub_7384 {
  strings:
    $key_7384 = { 27 ec [2] 53 f4 [2] 14 f6 [2] 53 e7 [2] 1d eb [2] 11 e1 [2] 06 ea [2] 1d a4 [2] 20 }

  condition:
    any of them
}