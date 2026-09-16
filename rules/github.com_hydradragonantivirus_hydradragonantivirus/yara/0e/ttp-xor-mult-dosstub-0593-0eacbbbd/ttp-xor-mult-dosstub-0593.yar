rule TTP_XOR_MULT_DOSStub_0593 {
  strings:
    $key_0593 = { 51 fb [2] 25 e3 [2] 62 e1 [2] 25 f0 [2] 6b fc [2] 67 f6 [2] 70 fd [2] 6b b3 [2] 56 }

  condition:
    any of them
}