rule TTP_XOR_MULT_DOSStub_0784 {
  strings:
    $key_0784 = { 53 ec [2] 27 f4 [2] 60 f6 [2] 27 e7 [2] 69 eb [2] 65 e1 [2] 72 ea [2] 69 a4 [2] 54 }

  condition:
    any of them
}