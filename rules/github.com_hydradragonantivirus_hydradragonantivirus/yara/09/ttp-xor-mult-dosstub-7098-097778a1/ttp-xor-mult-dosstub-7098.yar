rule TTP_XOR_MULT_DOSStub_7098 {
  strings:
    $key_7098 = { 24 f0 [2] 50 e8 [2] 17 ea [2] 50 fb [2] 1e f7 [2] 12 fd [2] 05 f6 [2] 1e b8 [2] 23 }

  condition:
    any of them
}