rule TTP_XOR_MULT_DOSStub_3984 {
  strings:
    $key_3984 = { 6d ec [2] 19 f4 [2] 5e f6 [2] 19 e7 [2] 57 eb [2] 5b e1 [2] 4c ea [2] 57 a4 [2] 6a }

  condition:
    any of them
}