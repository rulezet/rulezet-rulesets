rule TTP_XOR_MULT_DOSStub_1583 {
  strings:
    $key_1583 = { 41 eb [2] 35 f3 [2] 72 f1 [2] 35 e0 [2] 7b ec [2] 77 e6 [2] 60 ed [2] 7b a3 [2] 46 }

  condition:
    any of them
}