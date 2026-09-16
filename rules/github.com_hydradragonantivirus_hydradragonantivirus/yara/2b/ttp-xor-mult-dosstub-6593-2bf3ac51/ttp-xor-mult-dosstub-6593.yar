rule TTP_XOR_MULT_DOSStub_6593 {
  strings:
    $key_6593 = { 31 fb [2] 45 e3 [2] 02 e1 [2] 45 f0 [2] 0b fc [2] 07 f6 [2] 10 fd [2] 0b b3 [2] 36 }

  condition:
    any of them
}