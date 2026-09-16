rule TTP_XOR_MULT_DOSStub_f483 {
  strings:
    $key_f483 = { a0 eb [2] d4 f3 [2] 93 f1 [2] d4 e0 [2] 9a ec [2] 96 e6 [2] 81 ed [2] 9a a3 [2] a7 }

  condition:
    any of them
}