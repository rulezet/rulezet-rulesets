rule TTP_XOR_MULT_DOSStub_5798 {
  strings:
    $key_5798 = { 03 f0 [2] 77 e8 [2] 30 ea [2] 77 fb [2] 39 f7 [2] 35 fd [2] 22 f6 [2] 39 b8 [2] 04 }

  condition:
    any of them
}