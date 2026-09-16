rule TTP_XOR_MULT_DOSStub_0e96 {
  strings:
    $key_0e96 = { 5a fe [2] 2e e6 [2] 69 e4 [2] 2e f5 [2] 60 f9 [2] 6c f3 [2] 7b f8 [2] 60 b6 [2] 5d }

  condition:
    any of them
}