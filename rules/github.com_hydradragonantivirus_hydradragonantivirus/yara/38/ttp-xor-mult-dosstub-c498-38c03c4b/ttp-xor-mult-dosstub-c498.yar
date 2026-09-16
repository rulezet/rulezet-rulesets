rule TTP_XOR_MULT_DOSStub_c498 {
  strings:
    $key_c498 = { 90 f0 [2] e4 e8 [2] a3 ea [2] e4 fb [2] aa f7 [2] a6 fd [2] b1 f6 [2] aa b8 [2] 97 }

  condition:
    any of them
}