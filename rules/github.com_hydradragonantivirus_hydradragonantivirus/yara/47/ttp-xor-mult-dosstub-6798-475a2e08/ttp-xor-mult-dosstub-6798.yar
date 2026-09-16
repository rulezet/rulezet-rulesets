rule TTP_XOR_MULT_DOSStub_6798 {
  strings:
    $key_6798 = { 33 f0 [2] 47 e8 [2] 00 ea [2] 47 fb [2] 09 f7 [2] 05 fd [2] 12 f6 [2] 09 b8 [2] 34 }

  condition:
    any of them
}