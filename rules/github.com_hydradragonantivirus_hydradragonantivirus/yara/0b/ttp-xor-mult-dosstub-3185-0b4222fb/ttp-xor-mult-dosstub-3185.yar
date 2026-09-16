rule TTP_XOR_MULT_DOSStub_3185 {
  strings:
    $key_3185 = { 65 ed [2] 11 f5 [2] 56 f7 [2] 11 e6 [2] 5f ea [2] 53 e0 [2] 44 eb [2] 5f a5 [2] 62 }

  condition:
    any of them
}