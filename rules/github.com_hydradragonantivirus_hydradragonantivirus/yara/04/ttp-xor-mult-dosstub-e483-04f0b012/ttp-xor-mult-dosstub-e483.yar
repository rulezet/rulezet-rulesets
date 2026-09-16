rule TTP_XOR_MULT_DOSStub_e483 {
  strings:
    $key_e483 = { b0 eb [2] c4 f3 [2] 83 f1 [2] c4 e0 [2] 8a ec [2] 86 e6 [2] 91 ed [2] 8a a3 [2] b7 }

  condition:
    any of them
}