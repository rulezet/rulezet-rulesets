rule TTP_XOR_MULT_DOSStub_1085 {
  strings:
    $key_1085 = { 44 ed [2] 30 f5 [2] 77 f7 [2] 30 e6 [2] 7e ea [2] 72 e0 [2] 65 eb [2] 7e a5 [2] 43 }

  condition:
    any of them
}