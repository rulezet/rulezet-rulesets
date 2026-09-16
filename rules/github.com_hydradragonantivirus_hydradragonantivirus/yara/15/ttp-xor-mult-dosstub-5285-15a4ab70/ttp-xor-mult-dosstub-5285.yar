rule TTP_XOR_MULT_DOSStub_5285 {
  strings:
    $key_5285 = { 06 ed [2] 72 f5 [2] 35 f7 [2] 72 e6 [2] 3c ea [2] 30 e0 [2] 27 eb [2] 3c a5 [2] 01 }

  condition:
    any of them
}