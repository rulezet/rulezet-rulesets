rule TTP_XOR_MULT_DOSStub_1783 {
  strings:
    $key_1783 = { 43 eb [2] 37 f3 [2] 70 f1 [2] 37 e0 [2] 79 ec [2] 75 e6 [2] 62 ed [2] 79 a3 [2] 44 }

  condition:
    any of them
}