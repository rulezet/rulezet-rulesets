rule TTP_XOR_MULT_DOSStub_7483 {
  strings:
    $key_7483 = { 20 eb [2] 54 f3 [2] 13 f1 [2] 54 e0 [2] 1a ec [2] 16 e6 [2] 01 ed [2] 1a a3 [2] 27 }

  condition:
    any of them
}