rule TTP_XOR_MULT_DOSStub_1983 {
  strings:
    $key_1983 = { 4d eb [2] 39 f3 [2] 7e f1 [2] 39 e0 [2] 77 ec [2] 7b e6 [2] 6c ed [2] 77 a3 [2] 4a }

  condition:
    any of them
}