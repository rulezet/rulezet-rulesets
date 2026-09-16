rule TTP_XOR_MULT_DOSStub_7a84 {
  strings:
    $key_7a84 = { 2e ec [2] 5a f4 [2] 1d f6 [2] 5a e7 [2] 14 eb [2] 18 e1 [2] 0f ea [2] 14 a4 [2] 29 }

  condition:
    any of them
}