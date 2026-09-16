rule TTP_XOR_MULT_DOSStub_2984 {
  strings:
    $key_2984 = { 7d ec [2] 09 f4 [2] 4e f6 [2] 09 e7 [2] 47 eb [2] 4b e1 [2] 5c ea [2] 47 a4 [2] 7a }

  condition:
    any of them
}