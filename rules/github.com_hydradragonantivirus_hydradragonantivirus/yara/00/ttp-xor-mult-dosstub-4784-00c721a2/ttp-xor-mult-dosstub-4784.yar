rule TTP_XOR_MULT_DOSStub_4784 {
  strings:
    $key_4784 = { 13 ec [2] 67 f4 [2] 20 f6 [2] 67 e7 [2] 29 eb [2] 25 e1 [2] 32 ea [2] 29 a4 [2] 14 }

  condition:
    any of them
}