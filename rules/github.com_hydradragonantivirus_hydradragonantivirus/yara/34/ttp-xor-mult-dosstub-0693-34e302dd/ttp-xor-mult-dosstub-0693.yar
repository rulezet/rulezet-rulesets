rule TTP_XOR_MULT_DOSStub_0693 {
  strings:
    $key_0693 = { 52 fb [2] 26 e3 [2] 61 e1 [2] 26 f0 [2] 68 fc [2] 64 f6 [2] 73 fd [2] 68 b3 [2] 55 }

  condition:
    any of them
}