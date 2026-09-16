rule TTP_XOR_MULT_DOSStub_6285 {
  strings:
    $key_6285 = { 36 ed [2] 42 f5 [2] 05 f7 [2] 42 e6 [2] 0c ea [2] 00 e0 [2] 17 eb [2] 0c a5 [2] 31 }

  condition:
    any of them
}