rule TTP_XOR_MULT_DOSStub_2583 {
  strings:
    $key_2583 = { 71 eb [2] 05 f3 [2] 42 f1 [2] 05 e0 [2] 4b ec [2] 47 e6 [2] 50 ed [2] 4b a3 [2] 76 }

  condition:
    any of them
}