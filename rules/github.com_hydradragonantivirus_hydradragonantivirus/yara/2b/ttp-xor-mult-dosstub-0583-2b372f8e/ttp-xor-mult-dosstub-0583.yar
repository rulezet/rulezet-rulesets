rule TTP_XOR_MULT_DOSStub_0583 {
  strings:
    $key_0583 = { 51 eb [2] 25 f3 [2] 62 f1 [2] 25 e0 [2] 6b ec [2] 67 e6 [2] 70 ed [2] 6b a3 [2] 56 }

  condition:
    any of them
}