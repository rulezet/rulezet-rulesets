rule TTP_XOR_MULT_DOSStub_5e93 {
  strings:
    $key_5e93 = { 0a fb [2] 7e e3 [2] 39 e1 [2] 7e f0 [2] 30 fc [2] 3c f6 [2] 2b fd [2] 30 b3 [2] 0d }

  condition:
    any of them
}