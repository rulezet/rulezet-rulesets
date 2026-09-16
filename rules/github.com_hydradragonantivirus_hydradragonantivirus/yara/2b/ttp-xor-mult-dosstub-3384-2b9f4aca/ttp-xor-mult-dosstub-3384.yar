rule TTP_XOR_MULT_DOSStub_3384 {
  strings:
    $key_3384 = { 67 ec [2] 13 f4 [2] 54 f6 [2] 13 e7 [2] 5d eb [2] 51 e1 [2] 46 ea [2] 5d a4 [2] 60 }

  condition:
    any of them
}