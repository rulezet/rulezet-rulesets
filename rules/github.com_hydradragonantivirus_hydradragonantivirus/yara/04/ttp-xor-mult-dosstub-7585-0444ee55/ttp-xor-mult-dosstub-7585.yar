rule TTP_XOR_MULT_DOSStub_7585 {
  strings:
    $key_7585 = { 21 ed [2] 55 f5 [2] 12 f7 [2] 55 e6 [2] 1b ea [2] 17 e0 [2] 00 eb [2] 1b a5 [2] 26 }

  condition:
    any of them
}