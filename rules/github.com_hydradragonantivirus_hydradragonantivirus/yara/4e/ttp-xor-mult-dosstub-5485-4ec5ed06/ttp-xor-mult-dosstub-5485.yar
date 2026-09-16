rule TTP_XOR_MULT_DOSStub_5485 {
  strings:
    $key_5485 = { 00 ed [2] 74 f5 [2] 33 f7 [2] 74 e6 [2] 3a ea [2] 36 e0 [2] 21 eb [2] 3a a5 [2] 07 }

  condition:
    any of them
}