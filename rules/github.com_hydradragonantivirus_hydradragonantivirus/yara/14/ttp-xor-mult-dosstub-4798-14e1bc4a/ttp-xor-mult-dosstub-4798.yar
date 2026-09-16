rule TTP_XOR_MULT_DOSStub_4798 {
  strings:
    $key_4798 = { 13 f0 [2] 67 e8 [2] 20 ea [2] 67 fb [2] 29 f7 [2] 25 fd [2] 32 f6 [2] 29 b8 [2] 14 }

  condition:
    any of them
}