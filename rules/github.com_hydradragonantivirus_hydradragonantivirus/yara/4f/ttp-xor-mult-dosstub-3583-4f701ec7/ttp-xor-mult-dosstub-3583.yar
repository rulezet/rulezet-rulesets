rule TTP_XOR_MULT_DOSStub_3583 {
  strings:
    $key_3583 = { 61 eb [2] 15 f3 [2] 52 f1 [2] 15 e0 [2] 5b ec [2] 57 e6 [2] 40 ed [2] 5b a3 [2] 66 }

  condition:
    any of them
}