rule TTP_XOR_MULT_DOSStub_3385 {
  strings:
    $key_3385 = { 67 ed [2] 13 f5 [2] 54 f7 [2] 13 e6 [2] 5d ea [2] 51 e0 [2] 46 eb [2] 5d a5 [2] 60 }

  condition:
    any of them
}