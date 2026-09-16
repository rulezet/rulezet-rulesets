rule TTP_XOR_MULT_DOSStub_f098 {
  strings:
    $key_f098 = { a4 f0 [2] d0 e8 [2] 97 ea [2] d0 fb [2] 9e f7 [2] 92 fd [2] 85 f6 [2] 9e b8 [2] a3 }

  condition:
    any of them
}