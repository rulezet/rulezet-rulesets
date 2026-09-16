rule TTP_XOR_MULT_DOSStub_3585 {
  strings:
    $key_3585 = { 61 ed [2] 15 f5 [2] 52 f7 [2] 15 e6 [2] 5b ea [2] 57 e0 [2] 40 eb [2] 5b a5 [2] 66 }

  condition:
    any of them
}