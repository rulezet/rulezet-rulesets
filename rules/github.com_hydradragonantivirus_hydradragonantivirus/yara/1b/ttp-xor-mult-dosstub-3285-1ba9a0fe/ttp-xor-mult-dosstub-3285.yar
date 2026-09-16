rule TTP_XOR_MULT_DOSStub_3285 {
  strings:
    $key_3285 = { 66 ed [2] 12 f5 [2] 55 f7 [2] 12 e6 [2] 5c ea [2] 50 e0 [2] 47 eb [2] 5c a5 [2] 61 }

  condition:
    any of them
}