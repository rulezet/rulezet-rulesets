rule TTP_XOR_MULT_DOSStub_1098 {
  strings:
    $key_1098 = { 44 f0 [2] 30 e8 [2] 77 ea [2] 30 fb [2] 7e f7 [2] 72 fd [2] 65 f6 [2] 7e b8 [2] 43 }

  condition:
    any of them
}