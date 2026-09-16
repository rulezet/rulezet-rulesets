rule TTP_XOR_MULT_DOSStub_0285 {
  strings:
    $key_0285 = { 56 ed [2] 22 f5 [2] 65 f7 [2] 22 e6 [2] 6c ea [2] 60 e0 [2] 77 eb [2] 6c a5 [2] 51 }

  condition:
    any of them
}