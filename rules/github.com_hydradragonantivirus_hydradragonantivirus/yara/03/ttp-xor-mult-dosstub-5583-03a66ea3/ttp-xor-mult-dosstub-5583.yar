rule TTP_XOR_MULT_DOSStub_5583 {
  strings:
    $key_5583 = { 01 eb [2] 75 f3 [2] 32 f1 [2] 75 e0 [2] 3b ec [2] 37 e6 [2] 20 ed [2] 3b a3 [2] 06 }

  condition:
    any of them
}