rule TTP_XOR_MULT_DOSStub_0483 {
  strings:
    $key_0483 = { 50 eb [2] 24 f3 [2] 63 f1 [2] 24 e0 [2] 6a ec [2] 66 e6 [2] 71 ed [2] 6a a3 [2] 57 }

  condition:
    any of them
}