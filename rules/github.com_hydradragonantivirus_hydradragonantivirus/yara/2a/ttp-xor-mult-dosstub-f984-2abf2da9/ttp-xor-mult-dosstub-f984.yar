rule TTP_XOR_MULT_DOSStub_f984 {
  strings:
    $key_f984 = { ad ec [2] d9 f4 [2] 9e f6 [2] d9 e7 [2] 97 eb [2] 9b e1 [2] 8c ea [2] 97 a4 [2] aa }

  condition:
    any of them
}