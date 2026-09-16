rule TTP_XOR_MULT_DOSStub_1784 {
  strings:
    $key_1784 = { 43 ec [2] 37 f4 [2] 70 f6 [2] 37 e7 [2] 79 eb [2] 75 e1 [2] 62 ea [2] 79 a4 [2] 44 }

  condition:
    any of them
}