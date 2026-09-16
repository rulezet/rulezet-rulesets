rule TTP_XOR_MULT_DOSStub_6784 {
  strings:
    $key_6784 = { 33 ec [2] 47 f4 [2] 00 f6 [2] 47 e7 [2] 09 eb [2] 05 e1 [2] 12 ea [2] 09 a4 [2] 34 }

  condition:
    any of them
}