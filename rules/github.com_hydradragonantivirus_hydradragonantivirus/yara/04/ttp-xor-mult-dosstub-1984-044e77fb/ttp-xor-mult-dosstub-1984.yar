rule TTP_XOR_MULT_DOSStub_1984 {
  strings:
    $key_1984 = { 4d ec [2] 39 f4 [2] 7e f6 [2] 39 e7 [2] 77 eb [2] 7b e1 [2] 6c ea [2] 77 a4 [2] 4a }

  condition:
    any of them
}