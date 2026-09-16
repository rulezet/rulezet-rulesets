rule TTP_XOR_MULT_DOSStub_e098 {
  strings:
    $key_e098 = { b4 f0 [2] c0 e8 [2] 87 ea [2] c0 fb [2] 8e f7 [2] 82 fd [2] 95 f6 [2] 8e b8 [2] b3 }

  condition:
    any of them
}