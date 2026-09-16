rule TTP_XOR_MULT_DOSStub_1585 {
  strings:
    $key_1585 = { 41 ed [2] 35 f5 [2] 72 f7 [2] 35 e6 [2] 7b ea [2] 77 e0 [2] 60 eb [2] 7b a5 [2] 46 }

  condition:
    any of them
}