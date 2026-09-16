rule TTP_XOR_MULT_DOSStub_0e90 {
  strings:
    $key_0e90 = { 5a f8 [2] 2e e0 [2] 69 e2 [2] 2e f3 [2] 60 ff [2] 6c f5 [2] 7b fe [2] 60 b0 [2] 5d }

  condition:
    any of them
}