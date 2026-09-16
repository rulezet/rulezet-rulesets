rule TTP_XOR_MULT_DOSStub_3485 {
  strings:
    $key_3485 = { 60 ed [2] 14 f5 [2] 53 f7 [2] 14 e6 [2] 5a ea [2] 56 e0 [2] 41 eb [2] 5a a5 [2] 67 }

  condition:
    any of them
}