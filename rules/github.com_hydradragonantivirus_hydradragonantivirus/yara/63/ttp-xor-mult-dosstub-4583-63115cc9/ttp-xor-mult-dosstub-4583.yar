rule TTP_XOR_MULT_DOSStub_4583 {
  strings:
    $key_4583 = { 11 eb [2] 65 f3 [2] 22 f1 [2] 65 e0 [2] 2b ec [2] 27 e6 [2] 30 ed [2] 2b a3 [2] 16 }

  condition:
    any of them
}