rule TTP_XOR_MULT_DOSStub_5e90 {
  strings:
    $key_5e90 = { 0a f8 [2] 7e e0 [2] 39 e2 [2] 7e f3 [2] 30 ff [2] 3c f5 [2] 2b fe [2] 30 b0 [2] 0d }

  condition:
    any of them
}