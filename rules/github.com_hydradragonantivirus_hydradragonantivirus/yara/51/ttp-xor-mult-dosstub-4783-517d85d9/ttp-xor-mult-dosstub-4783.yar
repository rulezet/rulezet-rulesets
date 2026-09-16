rule TTP_XOR_MULT_DOSStub_4783 {
  strings:
    $key_4783 = { 13 eb [2] 67 f3 [2] 20 f1 [2] 67 e0 [2] 29 ec [2] 25 e6 [2] 32 ed [2] 29 a3 [2] 14 }

  condition:
    any of them
}