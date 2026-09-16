rule TTP_XOR_MULT_DOSStub_0884 {
  strings:
    $key_0884 = { 5c ec [2] 28 f4 [2] 6f f6 [2] 28 e7 [2] 66 eb [2] 6a e1 [2] 7d ea [2] 66 a4 [2] 5b }

  condition:
    any of them
}