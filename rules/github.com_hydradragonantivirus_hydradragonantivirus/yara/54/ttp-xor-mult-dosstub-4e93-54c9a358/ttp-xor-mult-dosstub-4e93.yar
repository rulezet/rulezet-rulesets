rule TTP_XOR_MULT_DOSStub_4e93 {
  strings:
    $key_4e93 = { 1a fb [2] 6e e3 [2] 29 e1 [2] 6e f0 [2] 20 fc [2] 2c f6 [2] 3b fd [2] 20 b3 [2] 1d }

  condition:
    any of them
}