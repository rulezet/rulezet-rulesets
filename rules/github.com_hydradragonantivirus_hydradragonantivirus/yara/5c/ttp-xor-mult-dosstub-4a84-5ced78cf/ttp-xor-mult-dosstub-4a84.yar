rule TTP_XOR_MULT_DOSStub_4a84 {
  strings:
    $key_4a84 = { 1e ec [2] 6a f4 [2] 2d f6 [2] 6a e7 [2] 24 eb [2] 28 e1 [2] 3f ea [2] 24 a4 [2] 19 }

  condition:
    any of them
}