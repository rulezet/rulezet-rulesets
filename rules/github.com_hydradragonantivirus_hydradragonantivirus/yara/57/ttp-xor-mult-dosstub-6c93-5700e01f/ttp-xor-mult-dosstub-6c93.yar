rule TTP_XOR_MULT_DOSStub_6c93 {
  strings:
    $key_6c93 = { 38 fb [2] 4c e3 [2] 0b e1 [2] 4c f0 [2] 02 fc [2] 0e f6 [2] 19 fd [2] 02 b3 [2] 3f }

  condition:
    any of them
}