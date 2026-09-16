rule TTP_XOR_MULT_DOSStub_2a84 {
  strings:
    $key_2a84 = { 7e ec [2] 0a f4 [2] 4d f6 [2] 0a e7 [2] 44 eb [2] 48 e1 [2] 5f ea [2] 44 a4 [2] 79 }

  condition:
    any of them
}