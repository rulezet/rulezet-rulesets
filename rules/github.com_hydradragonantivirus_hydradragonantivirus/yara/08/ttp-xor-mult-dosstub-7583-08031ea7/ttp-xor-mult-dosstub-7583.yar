rule TTP_XOR_MULT_DOSStub_7583 {
  strings:
    $key_7583 = { 21 eb [2] 55 f3 [2] 12 f1 [2] 55 e0 [2] 1b ec [2] 17 e6 [2] 00 ed [2] 1b a3 [2] 26 }

  condition:
    any of them
}