rule TTP_XOR_MULT_DOSStub_0885 {
  strings:
    $key_0885 = { 5c ed [2] 28 f5 [2] 6f f7 [2] 28 e6 [2] 66 ea [2] 6a e0 [2] 7d eb [2] 66 a5 [2] 5b }

  condition:
    any of them
}