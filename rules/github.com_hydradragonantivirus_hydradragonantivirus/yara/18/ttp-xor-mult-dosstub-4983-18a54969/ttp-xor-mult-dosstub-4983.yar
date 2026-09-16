rule TTP_XOR_MULT_DOSStub_4983 {
  strings:
    $key_4983 = { 1d eb [2] 69 f3 [2] 2e f1 [2] 69 e0 [2] 27 ec [2] 2b e6 [2] 3c ed [2] 27 a3 [2] 1a }

  condition:
    any of them
}