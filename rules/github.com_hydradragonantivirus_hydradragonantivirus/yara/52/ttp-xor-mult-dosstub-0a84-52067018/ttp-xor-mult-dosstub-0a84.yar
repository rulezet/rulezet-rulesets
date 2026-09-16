rule TTP_XOR_MULT_DOSStub_0a84 {
  strings:
    $key_0a84 = { 5e ec [2] 2a f4 [2] 6d f6 [2] 2a e7 [2] 64 eb [2] 68 e1 [2] 7f ea [2] 64 a4 [2] 59 }

  condition:
    any of them
}