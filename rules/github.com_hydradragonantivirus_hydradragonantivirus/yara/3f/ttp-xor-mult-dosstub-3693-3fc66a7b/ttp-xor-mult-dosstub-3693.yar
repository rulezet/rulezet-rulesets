rule TTP_XOR_MULT_DOSStub_3693 {
  strings:
    $key_3693 = { 62 fb [2] 16 e3 [2] 51 e1 [2] 16 f0 [2] 58 fc [2] 54 f6 [2] 43 fd [2] 58 b3 [2] 65 }

  condition:
    any of them
}