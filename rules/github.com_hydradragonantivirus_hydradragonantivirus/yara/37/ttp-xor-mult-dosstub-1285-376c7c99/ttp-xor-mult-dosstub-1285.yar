rule TTP_XOR_MULT_DOSStub_1285 {
  strings:
    $key_1285 = { 46 ed [2] 32 f5 [2] 75 f7 [2] 32 e6 [2] 7c ea [2] 70 e0 [2] 67 eb [2] 7c a5 [2] 41 }

  condition:
    any of them
}